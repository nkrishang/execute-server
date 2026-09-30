//! Layered configuration: `config/default.toml` → `config/<EXECUTE_PROFILE>.toml` →
//! `EXECUTE_<SECTION>__<KEY>` environment overrides, plus `PORT` and `DATABASE_URL` as Railway provides them.

use std::collections::BTreeMap;
use std::path::Path;

use alloy_primitives::Address;
use anyhow::{Context, bail};
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub privy: PrivyConfig,
    pub credentials: CredentialsConfig,
    pub addresses: AddressesConfig,
    pub indexer: IndexerConfig,
    pub engine: EngineConfig,
    pub webhooks: WebhooksConfig,
    pub outbox: OutboxConfig,
    pub reconciler: ReconcilerConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub chains: BTreeMap<String, ChainConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    pub callback_base_url: String,
    pub request_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub max_in_flight: usize,
    pub shutdown_grace_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_ms: u64,
    pub auto_migrate: bool,
    /// Session limits on every pooled connection (0 disables one). See `db`.
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
    pub idle_in_transaction_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivyConfig {
    pub app_id: String,
    pub verification_key: String,
    pub clock_skew_secs: u64,
}

/// Secret API keys (servers) and publishable client IDs (browsers).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialsConfig {
    /// A credential is cached after a successful lookup. A rotated key or client ID, or changed
    /// allowed origins, take effect on this instance at once and on the others within this TTL.
    pub cache_ttl_secs: u64,
    pub api_key_rate_limit_per_second: u32,
    pub api_key_rate_limit_burst: u32,
    pub client_id_rate_limit_per_second: u32,
    pub client_id_rate_limit_burst: u32,
    /// How many origins one client ID may be allowed from.
    pub max_allowed_origins: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressesConfig {
    /// The PaymentFactory generation `/v1` is pinned to, identical on every supported chain.
    pub factory_address: String,
    /// `expirationTimestamp` must be at least this far in the future…
    pub min_expiry_lead_secs: u64,
    /// …and at most this far: also the longest funds wait if the calls cannot run.
    pub max_expiry_lead_secs: u64,
    /// The address stays watched this long after it expires, so a payment that arrives late is still
    /// seen and returned to `recovery`.
    pub late_payment_window_secs: u64,
    /// An execute that reverts is retried with exponential backoff from this delay…
    pub execute_retry_base_ms: u64,
    /// …up to this one.
    pub execute_retry_cap_ms: u64,
    /// A refund is submitted this long after expiry at the earliest, so the chain's clock has passed
    /// `expirationTimestamp` too and the payment refunds rather than settles.
    pub expiry_margin_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IndexerConfig {
    pub base_url: String,
    pub webhook_secret: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    pub base_url: String,
    pub webhook_secret: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhooksConfig {
    /// How old an inbound X-Gum-Signature timestamp may be.
    pub inbound_tolerance_secs: i64,
    pub allow_insecure_targets: bool,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub retry_base_ms: u64,
    pub retry_cap_ms: u64,
    pub max_age_secs: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutboxConfig {
    pub workers: usize,
    pub poll_interval_ms: u64,
    pub batch_size: i64,
    pub lock_ttl_secs: i64,
    /// Backoff cap for jobs towards gum-indexer / gum-engine. These never give up.
    pub upstream_retry_cap_ms: u64,
    /// Longest a single job may run before it is abandoned and retried. Below `lock_ttl_secs`.
    pub job_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReconcilerConfig {
    pub interval_secs: u64,
    /// How often expired addresses are moved on (refunded or expired). Expiries are minutes away,
    /// so this runs far more often than the rest of the reconciler.
    pub expiry_interval_secs: u64,
    /// An execute job this old without a result is polled from gum-engine…
    pub in_flight_stale_secs: i64,
    /// …and polled again at most this often.
    pub in_flight_repoll_secs: i64,
    /// An address awaiting funds that has not changed for this long is checked against its watch.
    pub open_stale_secs: i64,
    /// How often this service's token list is compared with gum-indexer's.
    pub token_check_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    pub chain_id: u64,
    /// Offered for new addresses. A chain ships disabled and is turned on with
    /// `EXECUTE_CHAINS__<NAME>__ENABLED=true` once the factory generation is deployed on it and
    /// gum-indexer and gum-engine serve it. Addresses already created on it carry on either way.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Tokens an address may be funded with. gum-indexer must watch every one of them.
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenConfig {
    pub symbol: String,
    pub address: Address,
    pub decimals: u8,
}

impl Config {
    /// Loads configuration from `config_dir`, honouring `EXECUTE_PROFILE`, `EXECUTE_*`, `PORT` and `DATABASE_URL`.
    pub fn load(config_dir: &Path) -> anyhow::Result<Self> {
        let config = Self::load_unchecked(config_dir)?;
        config.validate()?;
        Ok(config)
    }

    /// [`Config::load`] without [`Config::validate`]; for tests that fill in the blanks themselves.
    pub fn load_unchecked(config_dir: &Path) -> anyhow::Result<Self> {
        let mut figment = Figment::from(Toml::file(config_dir.join("default.toml")));
        if let Ok(profile) = std::env::var("EXECUTE_PROFILE") {
            let path = config_dir.join(format!("{profile}.toml"));
            if !path.exists() {
                bail!("EXECUTE_PROFILE={profile} but {} does not exist", path.display());
            }
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(Env::prefixed("EXECUTE_").split("__"));
        if let Ok(port) = std::env::var("PORT") {
            let port: u16 = port.parse().context("PORT is not a valid port")?;
            figment = figment.merge(Serialized::default("server.port", port));
        }
        if let Ok(url) = std::env::var("DATABASE_URL") {
            figment = figment.merge(Serialized::default("database.url", url));
        }
        let mut config: Config = figment.extract().context("invalid configuration")?;
        // Railway and most dashboards store multi-line secrets with literal "\n".
        config.privy.verification_key = config.privy.verification_key.replace("\\n", "\n");
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.database.url.is_empty() {
            bail!("DATABASE_URL is required");
        }
        if !self.chains.values().any(|c| c.enabled) {
            bail!("at least one chain must be enabled");
        }
        let mut chain_ids = BTreeMap::new();
        for (name, chain) in &self.chains {
            if let Some(other) = chain_ids.insert(chain.chain_id, name) {
                bail!("chains {other} and {name} share chain_id {}", chain.chain_id);
            }
            if chain.tokens.is_empty() {
                bail!("chain {name} has no tokens");
            }
            let mut symbols = std::collections::BTreeSet::new();
            let mut addresses = std::collections::BTreeSet::new();
            for t in &chain.tokens {
                if !symbols.insert(t.symbol.to_ascii_uppercase()) || !addresses.insert(t.address) {
                    bail!("chain {name}: duplicate token {}", t.symbol);
                }
                if t.address.is_zero() {
                    bail!("chain {name}: token {} has the zero address", t.symbol);
                }
            }
        }
        self.factory_address().context("addresses.factory_address")?;
        let a = &self.addresses;
        if a.min_expiry_lead_secs == 0 || a.min_expiry_lead_secs >= a.max_expiry_lead_secs {
            bail!("addresses.min_expiry_lead_secs must be above 0 and below addresses.max_expiry_lead_secs");
        }
        if a.execute_retry_base_ms == 0 || a.execute_retry_base_ms > a.execute_retry_cap_ms {
            bail!("addresses.execute_retry_base_ms must be above 0 and at most addresses.execute_retry_cap_ms");
        }
        if self.outbox.workers == 0 {
            bail!("outbox.workers must be at least 1");
        }
        if self.outbox.job_timeout_ms == 0
            || self.outbox.job_timeout_ms >= self.outbox.lock_ttl_secs.max(0) as u64 * 1000
        {
            bail!("outbox.job_timeout_ms must be above 0 and below outbox.lock_ttl_secs");
        }
        Ok(())
    }

    pub fn factory_address(&self) -> anyhow::Result<Address> {
        let address: Address = self.addresses.factory_address.trim().parse().context("not a valid EVM address")?;
        if address.is_zero() {
            bail!("must not be the zero address");
        }
        Ok(address)
    }

    /// Warnings for settings that are legal in development but will not work in production.
    pub fn production_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.server.callback_base_url.is_empty() {
            out.push("server.callback_base_url is empty: gum-indexer / gum-engine cannot call back".into());
        }
        if self.privy.app_id.is_empty() || self.privy.verification_key.is_empty() {
            out.push("privy.app_id / privy.verification_key are empty: the dashboard routes refuse everything".into());
        }
        if self.indexer.base_url.is_empty() {
            out.push("indexer.base_url is empty: watches cannot be registered".into());
        }
        if self.engine.base_url.is_empty() {
            out.push("engine.base_url is empty: addresses cannot be executed".into());
        }
        if self.indexer.webhook_secret.is_empty() || self.engine.webhook_secret.is_empty() {
            out.push(
                "indexer.webhook_secret / engine.webhook_secret are empty: inbound webhooks will be rejected".into(),
            );
        }
        if self.webhooks.allow_insecure_targets {
            out.push("webhooks.allow_insecure_targets is on: app webhooks may target private hosts".into());
        }
        out
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_with(overrides: &str) -> anyhow::Result<Config> {
        let config: Config = Figment::from(Toml::string(include_str!("../config/default.toml")))
            .merge(Toml::string(
                "[database]\nurl = \"postgres://x\"\n[addresses]\nfactory_address = \"0x6D85B9706D8f076cB8A9fEA37d70Fcb8D22C2952\"",
            ))
            .merge(Toml::string(overrides))
            .extract()?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn default_config_is_valid_and_bounds_expiry_to_five_minutes() {
        let config = default_with("").unwrap();
        assert_eq!(config.addresses.max_expiry_lead_secs, 300);
        assert!(!config.chains["arc"].enabled);
        assert!(["monad", "arbitrum", "base"].iter().all(|c| config.chains[*c].enabled));
        // Stablecoins have 6 decimals; vault share tokens (for Switch) have ERC-4626's 18.
        let with = |chain: &str, decimals: u8| -> Vec<&str> {
            config.chains[chain].tokens.iter().filter(|t| t.decimals == decimals).map(|t| t.symbol.as_str()).collect()
        };
        assert_eq!(with("base", 6), ["USDC"]);
        assert_eq!(with("monad", 6), ["USDC", "USDT", "AUSD"]);
        assert!(["base", "monad", "arc"].iter().all(|c| !with(c, 18).is_empty()));
        assert!(with("arbitrum", 18).is_empty());
        assert!(config.chains.values().all(|c| c.tokens.iter().all(|t| t.decimals == 6 || t.decimals == 18)));
    }

    #[test]
    fn chains_and_bounds_are_validated() {
        let err = |overrides: &str| default_with(overrides).unwrap_err().to_string();
        assert!(err("[chains.arc]\nchain_id = 8453").contains("share chain_id 8453"));
        assert!(err("[addresses]\nmin_expiry_lead_secs = 300").contains("min_expiry_lead_secs"));
        let mut config = default_with("").unwrap();
        let tokens = &mut config.chains.get_mut("base").unwrap().tokens;
        tokens.push(TokenConfig { symbol: "usdc".into(), address: Address::repeat_byte(1), decimals: 6 });
        assert!(config.validate().unwrap_err().to_string().contains("chain base: duplicate token usdc"));
    }
}
