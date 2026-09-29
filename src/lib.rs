//! execute-server: the Execute API.
//!
//! ```text
//! app ──POST /v1/address/create──▶ execute-server ──(outbox)──▶ gum-indexer  POST /v1/watches
//! wallet ──GET /v1/address/{a}──▶    │  ◀──── webhook ─────────┘   payment.* / threshold.reached
//!                                    ├──(outbox)──▶ gum-engine   POST /v1/transactions  PaymentFactory.execute
//!                                    │  ◀──── webhook ─────────┘   transaction.included / confirmed / failed
//!                                    └──(outbox)──▶ app webhooks   address.funded / settled / failing / refunded …
//! ```
//!
//! Creating an address is a CREATE2 computation and one database transaction; everything that
//! touches a chain is delegated, and driven by webhooks plus a transactional outbox.

pub mod account;
pub mod address;
pub mod app;
pub mod auth;
pub mod chain;
pub mod clients;
pub mod config;
pub mod db;
pub mod error;
pub mod intent;
pub mod outbox;
pub mod reconciler;
pub mod state;
pub mod supervise;
pub mod telemetry;
pub mod webhooks;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
