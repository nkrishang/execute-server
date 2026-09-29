//! Background tasks that must outlive any single failure.
//!
//! The outbox and the reconciler run for the life of the process, and nothing else notices if one
//! of them ends. On 2026-09-23 a panic killed the outbox task twice; the process stayed up and kept
//! answering, and no watch was registered and no settlement submitted until it was restarted.
//! Supervised, such a task is logged, counted (`execute_task_restarts_total`) and started again.

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Pause before restarting, so a task that fails immediately does not spin.
const RESTART_DELAY: Duration = Duration::from_secs(1);

/// Runs `make()` as a task, and a fresh one whenever it ends (a panic, or returning) while the
/// service is still running. The returned handle completes once the task ends after `shutdown`.
pub fn spawn<F, Fut>(name: &'static str, shutdown: CancellationToken, mut make: F) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let result = tokio::spawn(make()).await;
            if shutdown.is_cancelled() {
                return;
            }
            let reason = match result {
                Ok(()) => "returned".to_owned(),
                Err(err) if err.is_panic() => {
                    let payload = err.into_panic();
                    let message = payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                        .unwrap_or_default();
                    format!("panicked: {message}")
                }
                Err(err) => err.to_string(),
            };
            tracing::error!(task = name, reason, "background task stopped unexpectedly; restarting it");
            metrics::counter!("execute_task_restarts_total", "task" => name).increment(1);
            tokio::select! {
                _ = tokio::time::sleep(RESTART_DELAY) => {}
                _ = shutdown.cancelled() => return,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn a_task_that_panics_or_returns_is_started_again_until_shutdown() {
        let runs = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();
        let handle = {
            let (runs, shutdown) = (runs.clone(), shutdown.clone());
            spawn("test", shutdown.clone(), move || {
                let (runs, shutdown) = (runs.clone(), shutdown.clone());
                async move {
                    match runs.fetch_add(1, Ordering::SeqCst) {
                        0 => panic!("first run dies"),
                        1 => {} // second run returns early
                        _ => shutdown.cancelled().await,
                    }
                }
            })
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while runs.load(Ordering::SeqCst) < 3 {
            assert!(tokio::time::Instant::now() < deadline, "task was not restarted");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle).await.expect("supervisor stops on shutdown").unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 3, "not restarted after shutdown");
    }
}
