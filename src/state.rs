//! Shared application state: one `Arc` cloned into every handler and background task.

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::Address;
use metrics_exporter_prometheus::PrometheusHandle;
use moka::sync::Cache;
use sqlx::PgPool;
use tokio::sync::Notify;

use crate::auth::api_key::CredentialCache;
use crate::auth::privy::PrivyVerifier;
use crate::chain::Registry;
use crate::clients::engine::EngineClient;
use crate::clients::indexer::IndexerClient;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub config: Config,
    pub pool: PgPool,
    pub registry: Registry,
    pub privy: PrivyVerifier,
    pub credentials: CredentialCache,
    pub indexer: IndexerClient,
    pub engine: EngineClient,
    /// Client for app webhooks (separate pool and timeouts from upstream calls).
    pub webhook_http: reqwest::Client,
    pub factory: Address,
    pub metrics: PrometheusHandle,
    /// Woken after an outbox row is committed so workers pick it up without waiting for the poll tick.
    pub outbox_wake: Notify,
    /// Accounts / keys touched recently; throttles `last_seen_at` / `last_used_at` writes.
    pub touched: Cache<String, ()>,
}

impl AppState {
    pub fn new(config: Config, pool: PgPool, metrics: PrometheusHandle) -> anyhow::Result<Self> {
        let registry = Registry::from_config(&config.chains);
        let privy = PrivyVerifier::new(&config.privy)?;
        let credentials = CredentialCache::new(&config.credentials);
        let indexer = IndexerClient::new(&config.indexer)?;
        let engine = EngineClient::new(&config.engine)?;
        let webhook_http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(config.webhooks.connect_timeout_ms))
            .timeout(Duration::from_millis(config.webhooks.request_timeout_ms))
            .user_agent("execute-server-webhook/1")
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let factory = config.factory_address()?;
        Ok(Self(Arc::new(Inner {
            config,
            pool,
            registry,
            privy,
            credentials,
            indexer,
            engine,
            webhook_http,
            factory,
            metrics,
            outbox_wake: Notify::new(),
            touched: Cache::builder().max_capacity(100_000).time_to_live(Duration::from_secs(60)).build(),
        })))
    }

    pub fn webhook_url(&self, path: &str) -> String {
        format!("{}{path}", self.config.server.callback_base_url.trim_end_matches('/'))
    }

    /// Returns `true` the first time `key` is seen within a minute.
    pub fn first_touch(&self, key: String) -> bool {
        if self.touched.contains_key(&key) {
            return false;
        }
        self.touched.insert(key, ());
        true
    }
}

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
