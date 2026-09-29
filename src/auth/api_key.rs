//! Credentials: secret API keys (`exe_sk_<64 hex>`, stored as SHA-256 hashes) and publishable client
//! IDs (`exe_client_<32 hex>`, public by design), each looked up through a short-lived cache and rate
//! limited on its own token bucket.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use moka::sync::Cache;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::config::CredentialsConfig;

pub const KEY_PREFIX: &str = "exe_sk_";
pub const CLIENT_ID_PREFIX: &str = "exe_client_";

/// A freshly generated key. The secret is shown to its owner exactly once.
pub struct GeneratedKey {
    pub secret: String,
    pub hash: Vec<u8>,
    pub prefix: String,
}

pub fn generate_key() -> GeneratedKey {
    let secret = format!("{KEY_PREFIX}{}", random_hex(32));
    let prefix = secret[..KEY_PREFIX.len() + 8].to_owned();
    GeneratedKey { hash: hash(&secret), secret, prefix }
}

pub fn generate_client_id() -> String {
    format!("{CLIENT_ID_PREFIX}{}", random_hex(16))
}

pub fn generate_webhook_secret() -> String {
    format!("whsec_{}", random_hex(32))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

pub fn looks_like_key(candidate: &str) -> bool {
    candidate.starts_with(KEY_PREFIX)
}

/// What a client ID resolves to: its account, and where it may be used from.
#[derive(Debug, Clone)]
pub struct ClientIdOwner {
    pub account_id: String,
    pub allowed_origins: Vec<String>,
}

type KeyedLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Positive caches from credential to owner, plus a token bucket per credential.
pub struct CredentialCache {
    keys: Cache<Vec<u8>, Arc<String>>,
    client_ids: Cache<String, Arc<ClientIdOwner>>,
    key_limiter: KeyedLimiter,
    client_limiter: KeyedLimiter,
}

impl CredentialCache {
    pub fn new(cfg: &CredentialsConfig) -> Self {
        let quota = |per_second: u32, burst: u32| {
            Quota::per_second(NonZeroU32::new(per_second.max(1)).unwrap())
                .allow_burst(NonZeroU32::new(burst.max(1)).unwrap())
        };
        let ttl = Duration::from_secs(cfg.cache_ttl_secs);
        Self {
            keys: Cache::builder().max_capacity(100_000).time_to_live(ttl).build(),
            client_ids: Cache::builder().max_capacity(100_000).time_to_live(ttl).build(),
            key_limiter: RateLimiter::keyed(quota(cfg.api_key_rate_limit_per_second, cfg.api_key_rate_limit_burst)),
            client_limiter: RateLimiter::keyed(quota(
                cfg.client_id_rate_limit_per_second,
                cfg.client_id_rate_limit_burst,
            )),
        }
    }

    /// The account id behind a key hash.
    pub fn key(&self, key_hash: &[u8]) -> Option<Arc<String>> {
        self.keys.get(key_hash)
    }

    pub fn insert_key(&self, key_hash: Vec<u8>, account_id: String) -> Arc<String> {
        let owner = Arc::new(account_id);
        self.keys.insert(key_hash, owner.clone());
        owner
    }

    pub fn invalidate_key(&self, key_hash: &[u8]) {
        self.keys.invalidate(key_hash);
    }

    pub fn client_id(&self, client_id: &str) -> Option<Arc<ClientIdOwner>> {
        self.client_ids.get(client_id)
    }

    pub fn insert_client_id(&self, client_id: String, owner: ClientIdOwner) -> Arc<ClientIdOwner> {
        let owner = Arc::new(owner);
        self.client_ids.insert(client_id, owner.clone());
        owner
    }

    pub fn invalidate_client_id(&self, client_id: &str) {
        self.client_ids.invalidate(client_id);
    }

    /// `true` when the request fits the key's budget.
    pub fn allow_key(&self, key_hash: &[u8]) -> bool {
        self.key_limiter.check_key(&hex::encode(key_hash)).is_ok()
    }

    pub fn allow_client_id(&self, client_id: &str) -> bool {
        self.client_limiter.check_key(&client_id.to_owned()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_unique_and_prefixed() {
        let (a, b) = (generate_key(), generate_key());
        assert_ne!(a.secret, b.secret);
        assert!(looks_like_key(&a.secret));
        assert_eq!(a.secret.len(), KEY_PREFIX.len() + 64);
        assert_eq!(a.prefix.len(), KEY_PREFIX.len() + 8);
        assert_eq!(a.hash, hash(&a.secret));
        let client_id = generate_client_id();
        assert!(client_id.starts_with(CLIENT_ID_PREFIX) && client_id.len() == CLIENT_ID_PREFIX.len() + 32);
        assert!(!looks_like_key(&client_id));
    }

    #[test]
    fn caches_and_buckets() {
        let cache = CredentialCache::new(&CredentialsConfig {
            cache_ttl_secs: 60,
            api_key_rate_limit_per_second: 1,
            api_key_rate_limit_burst: 2,
            client_id_rate_limit_per_second: 1,
            client_id_rate_limit_burst: 1,
            max_allowed_origins: 20,
        });
        let h = hash("exe_sk_x");
        cache.insert_key(h.clone(), "acct".into());
        assert_eq!(cache.key(&h).unwrap().as_str(), "acct");
        cache.invalidate_key(&h);
        assert!(cache.key(&h).is_none());
        assert!(cache.allow_key(&h) && cache.allow_key(&h));
        assert!(!cache.allow_key(&h), "burst of 2 exhausted");
        assert!(cache.allow_client_id("exe_client_a"));
        assert!(!cache.allow_client_id("exe_client_a"));
        assert!(cache.allow_client_id("exe_client_b"), "buckets are per credential");
    }
}
