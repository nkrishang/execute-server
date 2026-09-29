//! Outbox workers: the only place this service talks to gum-indexer, gum-engine or an app's webhook.
//! Jobs are claimed with `FOR UPDATE SKIP LOCKED`, so any number of instances can run workers; per
//! (address, kind) they run in creation order, so an app never sees `address.settled` before
//! `address.funded`.
//!
//! Nothing here waits without a limit: each job runs under `outbox.job_timeout_ms` and each claim
//! under `CLAIM_TIMEOUT`, on top of the session limits every connection carries (see `db`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::FromRow;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

use crate::address::store::{self, Failure};
use crate::clients::UpstreamError;
use crate::clients::engine::{SubmitTransaction, Webhook};
use crate::clients::indexer::CreateWatch;
use crate::config::Config;
use crate::state::AppState;
use crate::webhooks::sign;

const CLAIM_TIMEOUT: Duration = Duration::from_secs(10);
const RESCHEDULE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, FromRow)]
pub struct OutboxJob {
    pub id: Uuid,
    pub kind: String,
    pub address: String,
    pub payload: Value,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

enum Attempt {
    Done,
    /// Try again later; the message is stored on the row.
    Retry(String),
    /// Never try again.
    Dead(String),
}

pub async fn run(state: AppState, shutdown: CancellationToken) {
    let cfg = state.config.outbox.clone();
    let poll = Duration::from_millis(cfg.poll_interval_ms);
    let permits = Arc::new(Semaphore::new(cfg.workers));
    let job_timeout = Duration::from_millis(cfg.job_timeout_ms);
    tracing::info!(workers = cfg.workers, job_timeout_ms = cfg.job_timeout_ms, "outbox workers started");
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let claimed = tokio::time::timeout(CLAIM_TIMEOUT, claim(&state, cfg.batch_size, cfg.lock_ttl_secs))
            .await
            .unwrap_or_else(|_| Err(sqlx::Error::PoolTimedOut));
        let jobs = match claimed {
            Ok(jobs) => jobs,
            Err(err) => {
                tracing::error!(error = %err, "outbox claim failed");
                metrics::counter!("execute_db_errors_total", "kind" => "outbox_claim").increment(1);
                tokio::select! {
                    _ = tokio::time::sleep(poll) => continue,
                    _ = shutdown.cancelled() => break,
                }
            }
        };
        let full_batch = jobs.len() as i64 >= cfg.batch_size;
        let mut handles = Vec::with_capacity(jobs.len());
        for job in jobs {
            let permit = permits.clone().acquire_owned().await.expect("semaphore never closes");
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                run_bounded(state, job, job_timeout).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        if let Ok(Err(err)) = tokio::time::timeout(CLAIM_TIMEOUT, gauge(&state)).await {
            tracing::debug!(error = %err, "outbox gauge failed");
        }
        if full_batch {
            continue;
        }
        tokio::select! {
            _ = state.outbox_wake.notified() => {}
            _ = tokio::time::sleep(poll) => {}
            _ = shutdown.cancelled() => break,
        }
    }
    let _ = permits.acquire_many(cfg.workers as u32).await;
    tracing::info!("outbox workers stopped");
}

async fn claim(state: &AppState, batch: i64, lock_ttl_secs: i64) -> Result<Vec<OutboxJob>, sqlx::Error> {
    sqlx::query_as(
        "WITH due AS (
             SELECT o.id FROM outbox o
             WHERE o.dead_at IS NULL
               AND o.next_attempt_at <= now()
               AND (o.locked_until IS NULL OR o.locked_until < now())
               AND NOT EXISTS (
                   SELECT 1 FROM outbox p
                   WHERE p.address = o.address AND p.kind = o.kind AND p.id < o.id AND p.dead_at IS NULL
               )
             ORDER BY o.next_attempt_at
             LIMIT $1
             FOR UPDATE SKIP LOCKED
         )
         UPDATE outbox SET locked_until = now() + make_interval(secs => $2), attempts = attempts + 1
         FROM due WHERE outbox.id = due.id
         RETURNING outbox.id, outbox.kind, outbox.address, outbox.payload, outbox.attempts, outbox.created_at",
    )
    .bind(batch)
    .bind(lock_ttl_secs as f64)
    .fetch_all(&state.pool)
    .await
}

async fn gauge(state: &AppState) -> Result<(), sqlx::Error> {
    let (pending, dead): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE dead_at IS NULL), count(*) FILTER (WHERE dead_at IS NOT NULL) FROM outbox",
    )
    .fetch_one(&state.pool)
    .await?;
    metrics::gauge!("execute_outbox_pending").set(pending as f64);
    metrics::gauge!("execute_outbox_dead").set(dead as f64);
    Ok(())
}

async fn run_bounded(state: AppState, job: OutboxJob, limit: Duration) {
    if tokio::time::timeout(limit, execute(state.clone(), job.clone())).await.is_ok() {
        return;
    }
    tracing::error!(job_id = %job.id, kind = %job.kind, address = %job.address, attempt = job.attempts, "outbox job timed out; abandoned and rescheduled");
    metrics::counter!("execute_outbox_jobs_total", "kind" => job.kind.clone(), "outcome" => "timeout").increment(1);
    let error = format!("timed out after {} ms", limit.as_millis());
    match tokio::time::timeout(RESCHEDULE_TIMEOUT, retry_later(&state, &job, error)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(job_id = %job.id, error = %err, "could not reschedule the abandoned job; its lock will expire")
        }
        Err(_) => tracing::warn!(job_id = %job.id, "rescheduling the abandoned job timed out; its lock will expire"),
    }
}

async fn execute(state: AppState, job: OutboxJob) {
    let span = tracing::info_span!("outbox_job", job_id = %job.id, kind = %job.kind, address = %job.address, attempt = job.attempts);
    execute_job(state, job).instrument(span).await
}

async fn execute_job(state: AppState, job: OutboxJob) {
    let started = Instant::now();
    metrics::histogram!("execute_outbox_lag_seconds", "kind" => job.kind.clone())
        .record((Utc::now() - job.created_at).num_milliseconds().max(0) as f64 / 1000.0);
    let attempt = match job.kind.as_str() {
        "register_watch" => register_watch(&state, &job).await,
        "submit_execute" => submit_execute(&state, &job).await,
        "notify_app" => notify_app(&state, &job).await,
        other => Attempt::Dead(format!("unknown job kind {other}")),
    };
    let outcome = match &attempt {
        Attempt::Done => "done",
        Attempt::Retry(_) => "retry",
        Attempt::Dead(_) => "dead",
    };
    metrics::histogram!("execute_outbox_job_duration_seconds", "kind" => job.kind.clone(), "outcome" => outcome)
        .record(started.elapsed().as_secs_f64());
    metrics::counter!("execute_outbox_jobs_total", "kind" => job.kind.clone(), "outcome" => outcome).increment(1);
    let result = match attempt {
        Attempt::Done => {
            sqlx::query("DELETE FROM outbox WHERE id = $1").bind(job.id).execute(&state.pool).await.map(|_| ())
        }
        Attempt::Retry(error) => retry_later(&state, &job, error).await,
        Attempt::Dead(error) => {
            tracing::error!(error, "outbox job dead");
            mark_dead(&state, job.id, &error).await
        }
    };
    if let Err(err) = result {
        tracing::error!(error = %err, "failed to finalise outbox job; the lock will expire and it will run again");
        metrics::counter!("execute_db_errors_total", "kind" => "outbox_finalise").increment(1);
    }
}

async fn retry_later(state: &AppState, job: &OutboxJob, error: String) -> Result<(), sqlx::Error> {
    let age = (Utc::now() - job.created_at).num_seconds();
    match schedule(&state.config, &job.kind, job.attempts, age, rand::random::<f64>()) {
        Schedule::Dead => {
            tracing::error!(error, age_secs = age, "outbox job exhausted its retry window");
            mark_dead(state, job.id, &error).await
        }
        Schedule::Retry(delay) => {
            tracing::warn!(error, retry_in_ms = delay.as_millis() as u64, "outbox job failed; will retry");
            sqlx::query(
                "UPDATE outbox SET next_attempt_at = now() + make_interval(secs => $2), locked_until = NULL, last_error = $3 WHERE id = $1",
            )
            .bind(job.id)
            .bind(delay.as_secs_f64())
            .bind(error)
            .execute(&state.pool)
            .await
            .map(|_| ())
        }
    }
}

async fn mark_dead(state: &AppState, id: Uuid, error: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE outbox SET dead_at = now(), locked_until = NULL, last_error = $2 WHERE id = $1")
        .bind(id)
        .bind(error)
        .execute(&state.pool)
        .await
        .map(|_| ())
}

#[derive(Debug, PartialEq)]
enum Schedule {
    Retry(Duration),
    Dead,
}

/// Jobs towards gum-indexer / gum-engine are on the critical path (an execute after expiry refunds
/// instead of settling), so they back off to a short cap and never die. App notifications back off
/// up to an hour and are given up on after `webhooks.max_age_secs`.
fn schedule(config: &Config, kind: &str, attempts: i32, age_secs: i64, jitter: f64) -> Schedule {
    let (cap_ms, max_age) = if kind == "notify_app" {
        (config.webhooks.retry_cap_ms, Some(config.webhooks.max_age_secs))
    } else {
        (config.outbox.upstream_retry_cap_ms, None)
    };
    if max_age.is_some_and(|max| age_secs > max) {
        return Schedule::Dead;
    }
    let base = config.webhooks.retry_base_ms as f64;
    let exp = base * 2f64.powi(attempts.saturating_sub(1).min(30));
    let upper = exp.min(cap_ms as f64);
    Schedule::Retry(Duration::from_millis((base + jitter * (upper - base).max(0.0)) as u64))
}

// ---------------------------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------------------------

async fn register_watch(state: &AppState, job: &OutboxJob) -> Attempt {
    let row = match store::get(&state.pool, &job.address).await {
        Ok(Some(r)) => r,
        Ok(None) => return Attempt::Dead("address no longer exists".into()),
        Err(e) => return Attempt::Retry(format!("load address: {e}")),
    };
    if row.watch_id.is_some() {
        return Attempt::Done;
    }
    if !state.indexer.is_configured() {
        return Attempt::Retry("indexer is not configured".into());
    }
    let late = chrono::Duration::seconds(state.config.addresses.late_payment_window_secs as i64);
    let endpoint = state.webhook_url("/v1/webhooks/indexer");
    let req = CreateWatch {
        payment_address: row.address(),
        chain: row.chain_id.to_string(),
        token: row.token.parse().expect("stored addresses are valid"),
        balance_threshold: row.amount.clone(),
        webhook_endpoint: &endpoint,
        // Watched past expiry so a late payment is still seen, and refunded.
        expires_at: row.expires_at + late,
        payments_since: row.created_at,
    };
    match state.indexer.create_watch(&req).await {
        Ok(watch) => {
            if let Err(e) = store::mark_watch_registered(&state.pool, &row.address, watch.id).await {
                return Attempt::Retry(format!("record watch: {e}"));
            }
            tracing::info!(watch_id = %watch.id, "watch registered");
            Attempt::Done
        }
        Err(err @ UpstreamError::Rejected { .. }) => {
            // gum-indexer will not watch this address (its token is not in gum-indexer's registry?):
            // nothing will detect a payment. Loud, and kept on the row.
            let message = err.to_string();
            tracing::error!(error = %message, token = %row.token, chain_id = row.chain_id, "gum-indexer refused the watch");
            match store::mark_watch_rejected(&state.pool, &row.address, &message).await {
                Ok(()) => Attempt::Dead(message),
                Err(e) => Attempt::Retry(format!("record rejection: {e}")),
            }
        }
        Err(err) => Attempt::Retry(err.to_string()),
    }
}

async fn submit_execute(state: &AppState, job: &OutboxJob) -> Attempt {
    let row = match store::get(&state.pool, &job.address).await {
        Ok(Some(r)) => r,
        Ok(None) => return Attempt::Dead("address no longer exists".into()),
        Err(e) => return Attempt::Retry(format!("load address: {e}")),
    };
    if !row.state.executes() || row.engine_job_id.is_some() {
        return Attempt::Done;
    }
    if !state.engine.is_configured() {
        return Attempt::Retry("engine is not configured".into());
    }
    let idempotency_key = job
        .payload
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("address:{}:execute:{}", row.address, job.id));
    let webhook_url = state.webhook_url("/v1/webhooks/engine");
    let req = SubmitTransaction {
        chain_id: row.chain_id as u64,
        to: state.factory,
        data: row.execute_calldata(),
        webhook: Webhook { url: &webhook_url },
    };
    match state.engine.submit(&req, &idempotency_key).await {
        Ok(submitted) => {
            if let Err(e) =
                store::mark_execute_submitted(&state.pool, &row.address, submitted.job_id, submitted.replayed).await
            {
                return Attempt::Retry(format!("record job: {e}"));
            }
            tracing::info!(engine_job_id = %submitted.job_id, replayed = submitted.replayed, state = row.state.as_str(), "execute submitted");
            Attempt::Done
        }
        Err(err @ UpstreamError::Rejected { .. }) => {
            // gum-engine refuses the transaction itself (e.g. an unsupported chain): retrying the same
            // submission cannot help.
            let message = err.to_string();
            let failure = Failure { code: "engine_rejected".into(), message: message.clone(), revert_data: None };
            let recorded = async {
                let mut tx = state.pool.begin().await?;
                store::apply_attempt_failed(&mut tx, &row.address, None, &failure, None, json!({ "error": message }))
                    .await?;
                tx.commit().await
            }
            .await;
            match recorded {
                Ok(()) => {
                    metrics::counter!("execute_execution_failures_total", "code" => "engine_rejected", "revert" => "none").increment(1);
                    state.outbox_wake.notify_one();
                    Attempt::Dead(message)
                }
                Err(e) => Attempt::Retry(format!("record failure: {e}")),
            }
        }
        Err(err) => Attempt::Retry(err.to_string()),
    }
}

async fn notify_app(state: &AppState, job: &OutboxJob) -> Attempt {
    let field = |name: &str| job.payload.get(name).and_then(Value::as_str).map(str::to_owned);
    let (Some(url), Some(account_id)) = (field("url"), field("account_id")) else {
        return Attempt::Dead("notify_app job without url or account".into());
    };
    let Some(body) = job.payload.get("body") else { return Attempt::Dead("notify_app job without body".into()) };
    let event_id = field("event_id").unwrap_or_default();
    let event_type = field("event_type").unwrap_or_default();

    let secret: Option<(String,)> = match sqlx::query_as("SELECT webhook_secret FROM accounts WHERE id = $1")
        .bind(&account_id)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(row) => row,
        Err(e) => return Attempt::Retry(format!("load secret: {e}")),
    };
    let Some((secret,)) = secret else { return Attempt::Dead("account not found".into()) };

    let raw = serde_json::to_vec(body).expect("json value serialises");
    let started = Instant::now();
    let response = state
        .webhook_http
        .post(&url)
        .header("content-type", "application/json")
        .header("x-execute-event-id", &event_id)
        .header("x-execute-event-type", &event_type)
        .header("x-execute-delivery-attempt", job.attempts.to_string())
        .header("x-execute-signature", sign::signature_header(&secret, Utc::now().timestamp(), &raw))
        .body(raw)
        .send()
        .await;
    let elapsed = started.elapsed().as_secs_f64();
    let (outcome, attempt) = match response {
        Ok(r) if r.status().is_success() => ("delivered", Attempt::Done),
        Ok(r) => ("rejected", Attempt::Retry(format!("app webhook responded {}", r.status()))),
        Err(e) => ("transport", Attempt::Retry(format!("app webhook unreachable: {e}"))),
    };
    metrics::counter!("execute_app_webhook_deliveries_total", "outcome" => outcome).increment(1);
    metrics::histogram!("execute_upstream_request_duration_seconds", "service" => "app", "op" => "notify", "outcome" => outcome)
        .record(elapsed);
    if matches!(attempt, Attempt::Done) {
        tracing::info!(event_type, "app webhook delivered");
    }
    attempt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn config() -> Config {
        let mut c = Config::load_unchecked(Path::new("config")).unwrap();
        c.webhooks.retry_base_ms = 1000;
        c.webhooks.retry_cap_ms = 3_600_000;
        c.webhooks.max_age_secs = 86_400;
        c.outbox.upstream_retry_cap_ms = 30_000;
        c
    }

    #[test]
    fn upstream_jobs_back_off_to_a_short_cap_and_never_die() {
        let c = config();
        assert_eq!(schedule(&c, "submit_execute", 1, 0, 1.0), Schedule::Retry(Duration::from_millis(1000)));
        assert_eq!(schedule(&c, "submit_execute", 3, 0, 1.0), Schedule::Retry(Duration::from_millis(4000)));
        assert_eq!(
            schedule(&c, "register_watch", 50, 10 * 86_400, 1.0),
            Schedule::Retry(Duration::from_millis(30_000))
        );
    }

    #[test]
    fn app_webhooks_back_off_to_an_hour_and_die_after_a_day() {
        let c = config();
        assert_eq!(schedule(&c, "notify_app", 20, 0, 1.0), Schedule::Retry(Duration::from_millis(3_600_000)));
        assert_eq!(schedule(&c, "notify_app", 20, 86_401, 1.0), Schedule::Dead);
    }
}
