//! Background loops that make the outcome independent of any single webhook.
//!
//! * **Expiry** (every `expiry_interval_secs`): an address past its expiry is moved on. A balance goes
//!   back to `recovery` (refunding), an empty address expires. Addresses live at most minutes, so this
//!   runs every couple of seconds.
//! * **Reconcile** (every `interval_secs`): quiet addresses awaiting funds are compared with
//!   gum-indexer's view of their watch, and execute jobs without a result are polled from gum-engine.
//!   A lost webhook is applied from there; a watch or job the other service no longer knows is
//!   registered or submitted again.
//! * **Tokens** (every `token_check_interval_secs`): every token this service accepts must be one
//!   gum-indexer watches, or payments of it would never be seen. A missing one is logged and counted.
//!
//! Every transition applied here is the same guarded transition a webhook would apply, so running the
//! loops on several replicas at once is safe.

use std::time::Duration;

use alloy_primitives::U256;
use chrono::Utc;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::address::store;
use crate::clients::UpstreamError;
use crate::state::AppState;
use crate::webhooks::inbound::{ExecuteOutcome, apply_outcome, retry_delay_ms};

const BATCH: i64 = 100;
/// A due outbox job this old means the outbox is not draining.
pub const OUTBOX_STALL_SECS: f64 = 120.0;
const TICK_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(state: AppState, shutdown: CancellationToken) {
    let interval = Duration::from_secs(state.config.reconciler.interval_secs.max(1));
    let expiry_interval = Duration::from_secs(state.config.reconciler.expiry_interval_secs.max(1));
    let token_interval = Duration::from_secs(state.config.reconciler.token_check_interval_secs.max(10));
    tracing::info!(
        interval_secs = interval.as_secs(),
        expiry_interval_secs = expiry_interval.as_secs(),
        "reconciler started"
    );
    let mut next_tick = tokio::time::Instant::now() + interval;
    let mut next_token_check = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(expiry_interval) => {}
            _ = shutdown.cancelled() => break,
        }
        match tokio::time::timeout(TICK_TIMEOUT, expire(&state)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(error = %err, "expiry pass failed"),
            Err(_) => tracing::error!("expiry pass timed out"),
        }
        let now = tokio::time::Instant::now();
        if now >= next_tick {
            next_tick = now + interval;
            match tokio::time::timeout(TICK_TIMEOUT, tick(&state)).await {
                Ok(Ok(())) => metrics::counter!("execute_reconciler_ticks_total", "outcome" => "ok").increment(1),
                Ok(Err(err)) => {
                    tracing::error!(error = %err, "reconciler tick failed");
                    metrics::counter!("execute_reconciler_ticks_total", "outcome" => "error").increment(1);
                }
                Err(_) => {
                    tracing::error!("reconciler tick timed out");
                    metrics::counter!("execute_reconciler_ticks_total", "outcome" => "timeout").increment(1);
                }
            }
        }
        if now >= next_token_check && state.indexer.is_configured() {
            next_token_check = now + token_interval;
            check_tokens(&state).await;
        }
    }
    tracing::info!("reconciler stopped");
}

/// Moves on addresses past their expiry. Public so tests can drive it.
pub async fn expire(state: &AppState) -> anyhow::Result<()> {
    let moved = store::expire_due(&state.pool, state.config.addresses.expiry_margin_secs, 500).await?;
    if moved > 0 {
        tracing::info!(moved, "expired addresses moved on");
        state.outbox_wake.notify_one();
    }
    Ok(())
}

/// One reconcile pass. Public so tests can drive it.
pub async fn tick(state: &AppState) -> anyhow::Result<()> {
    let (due, oldest_secs) = store::outbox_due(&state.pool).await?;
    metrics::gauge!("execute_outbox_due").set(due as f64);
    metrics::gauge!("execute_outbox_oldest_due_age_seconds").set(oldest_secs);
    if oldest_secs > OUTBOX_STALL_SECS {
        tracing::error!(due, oldest_due_age_secs = oldest_secs as u64, "outbox is not draining");
    }
    if state.indexer.is_configured() {
        reconcile_open(state).await?;
    }
    if state.engine.is_configured() {
        reconcile_in_flight(state).await?;
    }
    store::prune(&state.pool).await?;
    Ok(())
}

fn recovered(address: &str, what: &str) {
    tracing::warn!(address, what, "state recovered by polling instead of a webhook");
    metrics::counter!("execute_address_transitions_total", "event" => "reconciled").increment(1);
}

async fn reconcile_open(state: &AppState) -> anyhow::Result<()> {
    let stale = store::stale_open(&state.pool, state.config.reconciler.open_stale_secs, BATCH).await?;
    for row in stale {
        let Some(watch_id) = row.watch_id else { continue };
        let watch = match state.indexer.get_watch(watch_id).await {
            Ok(Some(watch)) => watch,
            Ok(None) => {
                tracing::error!(address = %row.address, %watch_id, "indexer does not know our watch; registering it again");
                if store::reregister_watch(&state.pool, &row.address).await? {
                    state.outbox_wake.notify_one();
                }
                continue;
            }
            Err(err @ UpstreamError::Rejected { .. }) => {
                tracing::error!(address = %row.address, error = %err, "indexer rejected the status request");
                continue;
            }
            Err(err) => {
                tracing::warn!(address = %row.address, error = %err, "indexer status unavailable");
                break;
            }
        };
        let confirmed = watch.confirmed();
        let ours = U256::from_str_radix(&row.balance, 10).unwrap_or_default();
        let data = json!({ "watch_id": watch_id, "polled_at": Utc::now(), "watch_status": watch.status, "confirmed_amount": confirmed.to_string(), "source": "reconciler" });
        let mut tx = state.pool.begin().await?;
        let changed = match watch.status.as_str() {
            "completed" => store::apply_threshold(&mut tx, &row.address, confirmed, data).await?.is_some(),
            "expired" | "cancelled" => {
                store::apply_watch_expired(&mut tx, &row.address, confirmed, data).await?.is_some()
            }
            _ if confirmed > ours => store::apply_confirmed(&mut tx, &row.address, confirmed, data).await?.is_some(),
            _ => false,
        };
        tx.commit().await?;
        if changed {
            recovered(&row.address, &watch.status);
            state.outbox_wake.notify_one();
        } else {
            store::touch(&state.pool, &row.address).await?;
        }
    }
    Ok(())
}

async fn reconcile_in_flight(state: &AppState) -> anyhow::Result<()> {
    // Execution takes seconds: an old in-flight job means gum-engine's webhooks are not landing.
    let (in_flight, oldest_secs) = store::in_flight_backlog(&state.pool).await?;
    metrics::gauge!("execute_addresses_in_flight").set(in_flight as f64);
    metrics::gauge!("execute_addresses_in_flight_oldest_age_seconds").set(oldest_secs);

    let cfg = &state.config.reconciler;
    let stale = store::stale_in_flight(&state.pool, cfg.in_flight_stale_secs, cfg.in_flight_repoll_secs, BATCH).await?;
    for row in stale {
        let Some(job_id) = row.engine_job_id else { continue };
        let job = match state.engine.get_job(job_id).await {
            Ok(Some(job)) => job,
            Ok(None) => {
                tracing::error!(address = %row.address, %job_id, "engine does not know our job; submitting again");
                let mut tx = state.pool.begin().await?;
                let delay = retry_delay_ms(&state.config.addresses, row.execute_attempts);
                let changed = store::retry_execute(
                    &mut tx,
                    &row.address,
                    job_id,
                    delay,
                    json!({ "reason": "engine_job_unknown" }),
                )
                .await?
                .is_some();
                tx.commit().await?;
                if changed {
                    state.outbox_wake.notify_one();
                }
                continue;
            }
            Err(err @ UpstreamError::Rejected { .. }) => {
                tracing::error!(address = %row.address, error = %err, "engine rejected the status request");
                continue;
            }
            Err(err) => {
                tracing::warn!(address = %row.address, error = %err, "engine status unavailable");
                break;
            }
        };
        let tx_hash = job.tx_hash.map(|h| format!("{h:#x}"));
        let data = json!({ "engine_job_id": job_id, "polled_at": Utc::now(), "status": job.status, "outcome": job.outcome, "tx_hash": tx_hash, "block_number": job.block_number, "source": "reconciler" });
        let outcome = match job.status.as_str() {
            "confirmed" => ExecuteOutcome::from_receipt(
                job.outcome.as_deref(),
                tx_hash,
                job.block_number.map(|n| n as i64),
                job.receipt.as_ref(),
                job.error.as_ref(),
                &row,
                data,
            ),
            "failed" => ExecuteOutcome::engine_failure(job.error.as_ref(), tx_hash, &row, data),
            _ => {
                store::touch(&state.pool, &row.address).await?;
                continue;
            }
        };
        let mut tx = state.pool.begin().await?;
        let changed = apply_outcome(&mut tx, &state.config.addresses, &row, job_id, outcome).await?;
        tx.commit().await?;
        if changed {
            recovered(&row.address, &job.status);
            state.outbox_wake.notify_one();
        }
    }
    Ok(())
}

/// Every token accepted here must be one gum-indexer watches on that chain.
async fn check_tokens(state: &AppState) {
    let indexed = match state.indexer.chains().await {
        Ok(chains) => chains,
        Err(err) => {
            tracing::warn!(error = %err, "could not read gum-indexer's tokens");
            return;
        }
    };
    let mut missing = 0usize;
    for chain in state.registry.chains() {
        let theirs = indexed.iter().find(|c| c.chain_id == chain.chain_id);
        for token in &chain.tokens {
            if !theirs.is_some_and(|c| c.tokens.iter().any(|t| t.address == token.address)) {
                missing += 1;
                tracing::error!(chain_id = chain.chain_id, token = %token.address, symbol = %token.symbol, "gum-indexer does not watch a token this service accepts: payments of it will not be seen");
            }
        }
    }
    metrics::gauge!("execute_tokens_unwatched").set(missing as f64);
}
