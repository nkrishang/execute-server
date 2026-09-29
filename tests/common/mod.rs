//! Test harness: a real server on a random port, a fresh database per test, and wiremock stand-ins for
//! gum-indexer, gum-engine and an app's webhook endpoint.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;
use execute_server::config::{ChainConfig, Config, TokenConfig};
use execute_server::state::AppState;
use execute_server::webhooks::sign;
use execute_server::{app, outbox, supervise};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub const PRIVY_APP_ID: &str = "test-app";
pub const INDEXER_SECRET: &str = "indexer-secret";
pub const ENGINE_SECRET: &str = "engine-secret";
pub const ADMIN_TOKEN: &str = "admin-token";
/// gum-contracts LocalBootstrap fixtures on Anvil.
pub const FACTORY: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
pub const USDC: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
pub const VAULT: &str = "0xbeef0e0834849aCC03f0089F01f4F1Eeb06873C9";
pub const USER: &str = "0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086";
pub const WATCH_ID: &str = "0193a1b2-0000-7000-8000-000000000001";

const PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU7hql39QEntx0whR
u9fUwJhXuy/iDeoMBKhKL1YrnIuhRANCAASJTbshE2SLSlSHIfUw7qrgjI7oQmm6
zUc8RblUTkKx6Gnwx4Ixw7EB9x3HtTogGCOSTXUyQ4b/qIblZbWMxl4m
-----END PRIVATE KEY-----
";
const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiU27IRNki0pUhyH1MO6q4IyO6EJp
us1HPEW5VE5Csehp8MeCMcOxAfcdx7U6IBgjkk11MkOG/6iG5WW1jMZeJg==
-----END PUBLIC KEY-----
";

pub struct Harness {
    pub base_url: String,
    pub http: reqwest::Client,
    pub pool: PgPool,
    pub state: AppState,
    pub indexer: MockServer,
    pub engine: MockServer,
    pub app: MockServer,
    shutdown: CancellationToken,
}

/// `TEST_DATABASE_URL` must point at a Postgres the tests may create databases on.
pub fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL").ok().filter(|s| !s.is_empty())
}

async fn fresh_database(admin_url: &str) -> String {
    let name = format!("execute_test_{}", uuid::Uuid::new_v4().simple());
    let admin = PgPoolOptions::new().max_connections(1).connect(admin_url).await.expect("admin connection");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.expect("create database");
    admin.close().await;
    let mut url = url::Url::parse(admin_url).expect("url");
    url.set_path(&format!("/{name}"));
    url.to_string()
}

/// Answers `POST /v1/transactions` with a fresh job id each time, as gum-engine does.
struct Jobs(Arc<AtomicU64>);

impl Respond for Jobs {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        ResponseTemplate::new(202).set_body_json(json!({ "job_id": job_id(n) }))
    }
}

/// The id of the `n`th job the engine stub accepted (UUIDv7-shaped, stamped now).
pub fn job_id(n: u64) -> String {
    let millis = Utc::now().timestamp_millis() as u64;
    format!("{:08x}-{:04x}-7000-8000-{:012x}", millis >> 16, millis & 0xffff, n)
}

impl Harness {
    pub async fn start() -> Option<Self> {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(tweak: impl FnOnce(&mut Config)) -> Option<Self> {
        let admin_url = test_database_url()?;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
            .with_test_writer()
            .try_init();
        let db_url = fresh_database(&admin_url).await;

        let indexer = MockServer::start().await;
        let engine = MockServer::start().await;
        let app_mock = MockServer::start().await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let mut config = Config::load_unchecked(Path::new("config")).expect("config/default.toml must load");
        config.server.callback_base_url = base_url.clone();
        config.database.url = db_url;
        config.privy.app_id = PRIVY_APP_ID.into();
        config.privy.verification_key = PUBLIC_KEY_PEM.into();
        config.addresses.factory_address = FACTORY.into();
        config.addresses.min_expiry_lead_secs = 1;
        config.addresses.expiry_margin_secs = 0;
        config.addresses.execute_retry_base_ms = 50;
        config.addresses.execute_retry_cap_ms = 200;
        config.indexer.base_url = indexer.uri();
        config.indexer.webhook_secret = INDEXER_SECRET.into();
        config.engine.base_url = engine.uri();
        config.engine.webhook_secret = ENGINE_SECRET.into();
        config.webhooks.allow_insecure_targets = true;
        config.webhooks.retry_base_ms = 50;
        config.webhooks.retry_cap_ms = 200;
        config.outbox.poll_interval_ms = 50;
        config.outbox.workers = 4;
        config.admin.token = ADMIN_TOKEN.into();
        config.chains = BTreeMap::from([(
            "anvil".to_owned(),
            ChainConfig {
                chain_id: 31337,
                enabled: true,
                tokens: vec![TokenConfig { symbol: "USDC".into(), address: USDC.parse().unwrap(), decimals: 6 }],
            },
        )]);
        tweak(&mut config);
        config.validate().expect("test config is valid");
        execute_server::db::migrate(&config.database).await.expect("migrations");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(execute_server::db::connect_options(&config.database).expect("connect options"))
            .await
            .expect("db");
        let state = AppState::new(config, pool.clone(), metrics_handle()).expect("state");
        let shutdown = CancellationToken::new();
        {
            let (state, shutdown) = (state.clone(), shutdown.clone());
            supervise::spawn("outbox", shutdown.clone(), move || outbox::run(state.clone(), shutdown.clone()));
        }
        let router = app::router(state.clone());
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move {
            axum::serve(listener, router).with_graceful_shutdown(server_shutdown.cancelled_owned()).await.unwrap();
        });

        let h = Self {
            base_url,
            http: reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap(),
            pool,
            state,
            indexer,
            engine,
            app: app_mock,
            shutdown,
        };
        h.mount_upstreams().await;
        Some(h)
    }

    async fn mount_upstreams(&self) {
        Mock::given(method("POST"))
            .and(path("/v1/watches"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": WATCH_ID, "chain_id": 31337, "payment_address": "0x0000000000000000000000000000000000000001",
                "status": "active", "confirmed_amount": "0"
            })))
            .mount(&self.indexer)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transactions"))
            .respond_with(Jobs(Arc::new(AtomicU64::new(0))))
            .mount(&self.engine)
            .await;
        Mock::given(method("POST")).and(path("/hooks")).respond_with(ResponseTemplate::new(200)).mount(&self.app).await;
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    pub fn privy_token(&self, sub: &str) -> String {
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            iss: &'a str,
            aud: &'a str,
            iat: i64,
            exp: i64,
            sid: &'a str,
        }
        let now = Utc::now().timestamp();
        let key = EncodingKey::from_ec_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();
        encode(
            &Header::new(Algorithm::ES256),
            &Claims { sub, iss: "privy.io", aud: PRIVY_APP_ID, iat: now, exp: now + 3600, sid: "s" },
            &key,
        )
        .unwrap()
    }

    /// The account as the dashboard sees it (creating it on first use).
    pub async fn account(&self, sub: &str) -> Value {
        let res = self.http.get(self.url("/v1/account")).bearer_auth(self.privy_token(sub)).send().await.unwrap();
        assert_eq!(res.status(), 200);
        res.json().await.unwrap()
    }

    /// Creates the account's API key through the dashboard route and returns the secret.
    pub async fn api_key(&self, sub: &str) -> String {
        let res =
            self.http.post(self.url("/v1/account/api-key")).bearer_auth(self.privy_token(sub)).send().await.unwrap();
        assert_eq!(res.status(), 201, "{}", res.text().await.unwrap());
        res.json::<Value>().await.unwrap()["apiKey"].as_str().unwrap().to_owned()
    }

    pub async fn set_webhook(&self, sub: &str) {
        let res = self
            .http
            .put(self.url("/v1/account/webhook-url"))
            .bearer_auth(self.privy_token(sub))
            .json(&json!({ "webhookUrl": format!("{}/hooks", self.app.uri()) }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    }

    pub async fn create(&self, key: &str, intent: &Value) -> reqwest::Response {
        self.http.post(self.url("/v1/address/create")).bearer_auth(key).json(intent).send().await.unwrap()
    }

    pub async fn status(&self, address: &str) -> Value {
        self.http.get(self.url(&format!("/v1/address/{address}/status"))).send().await.unwrap().json().await.unwrap()
    }

    /// Delivers a signed webhook the way gum-indexer / gum-engine would.
    pub async fn deliver(&self, path: &str, secret: &str, body: &Value) -> reqwest::Response {
        let raw = serde_json::to_vec(body).unwrap();
        self.http
            .post(self.url(path))
            .header("content-type", "application/json")
            .header("x-gum-signature", sign::signature_header(secret, Utc::now().timestamp(), &raw))
            .body(raw)
            .send()
            .await
            .unwrap()
    }

    /// Polls until `f` returns `Some`, or panics after `timeout`.
    pub async fn wait_for<T, F, Fut>(&self, what: &str, timeout: Duration, mut f: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(v) = f().await {
                return v;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Waits for the `n`th `POST /v1/transactions` and returns the job id the stub gave it.
    pub async fn engine_job(&self, n: usize) -> String {
        let engine = &self.engine;
        self.wait_for(&format!("execute submission {n}"), Duration::from_secs(5), || async move {
            let submissions = engine
                .received_requests()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.url.path() == "/v1/transactions")
                .count();
            (submissions >= n).then_some(())
        })
        .await;
        // The job the address now waits on.
        self.wait_for("the job id to be recorded", Duration::from_secs(5), || async {
            let row: Option<(Option<uuid::Uuid>, i32)> =
                sqlx::query_as("SELECT engine_job_id, execute_attempts FROM addresses LIMIT 1")
                    .fetch_optional(&self.pool)
                    .await
                    .unwrap();
            row.and_then(|(id, attempts)| (attempts as usize >= n).then_some(id).flatten()).map(|id| id.to_string())
        })
        .await
    }

    /// App webhook deliveries so far, verified against the account's secret.
    pub async fn app_deliveries(&self, secret: &str) -> Vec<Value> {
        let mut out = Vec::new();
        for req in self.app.received_requests().await.unwrap_or_default() {
            let header = req.headers.get("x-execute-signature").unwrap().to_str().unwrap();
            assert!(sign::verify(secret, header, &req.body, Utc::now().timestamp(), 300), "app webhook signature");
            out.push(serde_json::from_slice(&req.body).unwrap());
        }
        out
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    use std::sync::OnceLock;
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let _ = metrics::set_global_recorder(recorder);
            handle
        })
        .clone()
}

/// A deposit of 100 USDC into a vault, expiring `lead_secs` from now.
pub fn intent(lead_secs: u64) -> Value {
    json!({
        "token": USDC,
        "amount": "100000000",
        "calls": [
            { "target": USDC, "function": "approve(address spender, uint256 amount)", "args": [VAULT, "100000000"] },
            { "target": VAULT, "function": "deposit(uint256 assets, address receiver)", "args": ["100000000", USER] }
        ],
        "expirationTimestamp": Utc::now().timestamp() as u64 + lead_secs,
        "recovery": USER,
        "salt": format!("0x{}", hex::encode(rand_bytes())),
        "chainId": 31337
    })
}

fn rand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    let id = uuid::Uuid::new_v4();
    b[..16].copy_from_slice(id.as_bytes());
    b[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    b
}

pub fn indexer_event(id: &str, event_type: &str, address: &str, confirmed: &str) -> Value {
    json!({
        "id": id, "type": event_type, "created_at": Utc::now(), "sequence": 1,
        "watch": { "id": WATCH_ID, "chain": "anvil", "chain_id": 31337, "token": "USDC", "token_address": USDC,
                   "payment_address": address, "balance_threshold": "100000000", "confirmed_amount": confirmed, "status": "active" },
        "transfer": { "tx_hash": format!("0x{}", "ab".repeat(32)), "log_index": 0, "block_number": 7, "from": USER, "amount": confirmed, "status": "confirmed" },
    })
}

pub fn engine_event(
    event_id: &str,
    event: &str,
    job_id: &str,
    outcome: Option<&str>,
    receipt: Option<Value>,
    error: Option<Value>,
) -> Value {
    json!({
        "event_id": event_id, "event": event, "sequence": 1, "job_id": job_id, "chain_id": 31337,
        "outcome": outcome, "tx_hash": format!("0x{}", "cd".repeat(32)), "block_number": 9,
        "receipt": receipt, "error": error, "timestamp": Utc::now(),
    })
}

fn word(hex_value: &str) -> String {
    format!("0x{:0>64}", hex_value.trim_start_matches("0x"))
}

/// A receipt whose logs say the address settled `amount` of USDC.
pub fn settled_receipt(address: &str, amount: u64) -> Value {
    json!({ "status": "0x1", "logs": [{
        "address": address,
        "topics": ["0x7823e479a1a4ebe2418874847436f8a1680c5ee5b17f38bb59dbff28e1b45552", word(&USDC.to_ascii_lowercase())],
        "data": word(&format!("{amount:x}")),
    }]})
}

/// A receipt whose logs say the address (expired) sent `amount` of USDC to recovery.
pub fn recovered_receipt(address: &str, amount: u64) -> Value {
    json!({ "status": "0x1", "logs": [{
        "address": address,
        "topics": ["0xfff3b3844276f57024e0b42afec1a37f75db36511e43819a4f2a63ab7862b648", word(&USER.to_ascii_lowercase()), word(&USDC.to_ascii_lowercase())],
        "data": word(&format!("{amount:x}")),
    }]})
}
