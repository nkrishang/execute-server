//! Postgres connections. Every connection the service uses carries server-side limits, so no
//! database wait is unbounded: a statement queued behind a row lock fails after `lock_timeout_ms`,
//! any statement after `statement_timeout_ms`, and a transaction left open (e.g. by a dropped
//! request) is ended after `idle_in_transaction_timeout_ms`, releasing its locks. The callers turn
//! those errors into 503s or outbox retries. (2026-09-23: an outbox job waited on the database
//! with no limit and froze every settlement until the process was restarted.)
//!
//! Migrations are the exception: they may legitimately run long, so they use their own
//! connection without these limits.

use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};

use crate::config::DatabaseConfig;

/// Connection options with the configured session limits applied.
pub fn connect_options(cfg: &DatabaseConfig) -> anyhow::Result<PgConnectOptions> {
    let limits = [
        ("statement_timeout", cfg.statement_timeout_ms),
        ("lock_timeout", cfg.lock_timeout_ms),
        ("idle_in_transaction_session_timeout", cfg.idle_in_transaction_timeout_ms),
    ];
    let options = PgConnectOptions::from_str(&cfg.url).context("database.url is not a Postgres URL")?;
    Ok(options.options(limits.into_iter().filter(|(_, ms)| *ms > 0).map(|(k, ms)| (k, ms.to_string()))))
}

/// The service's pool: sized from config, every connection limited as above.
pub async fn connect(cfg: &DatabaseConfig) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_millis(cfg.acquire_timeout_ms))
        .connect_with(connect_options(cfg)?)
        .await
        .context("connecting to postgres")
}

/// Runs the migrations on a dedicated connection without the session limits.
pub async fn migrate(cfg: &DatabaseConfig) -> anyhow::Result<()> {
    let options = PgConnectOptions::from_str(&cfg.url).context("database.url is not a Postgres URL")?;
    let mut conn = PgConnection::connect_with(&options).await.context("connecting to postgres to migrate")?;
    crate::MIGRATOR.run(&mut conn).await.context("running migrations")?;
    conn.close().await.ok();
    Ok(())
}
