//! Executable addresses: the registry of intents the API has created, and each one's lifecycle.
//!
//! ```text
//! awaiting_funds ──balance reaches amount──▶ funded ──Settled──────────────▶ settled
//!       │                                      │  ▲
//!       │                                      ▼  │ retried with backoff
//!       │                                    failing
//!       │                                      │
//!       └──expiry: balance > 0──▶ refunding ◀──┘ expiry ──Recovered──▶ refunded
//!       └──expiry: nothing there──▶ expired ──a late payment──▶ refunding
//! ```
//!
//! An address's intent never changes; only its state does. Everything that happens is recorded on
//! the address's timeline, and the app-facing events are delivered to the webhooks of every account
//! that created it.

pub mod routes;
pub mod store;

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::SolCall;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::chain::payment::{Call, PaymentTerms};
use crate::chain::revert::RevertView;
use crate::intent::IntentJson;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, sqlx::Type)]
#[sqlx(type_name = "address_state", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AddressState {
    AwaitingFunds,
    Funded,
    Failing,
    Settled,
    Refunding,
    Refunded,
    Expired,
}

impl AddressState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingFunds => "awaiting_funds",
            Self::Funded => "funded",
            Self::Failing => "failing",
            Self::Settled => "settled",
            Self::Refunding => "refunding",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }

    /// An execute may be submitted in these states.
    pub fn executes(self) -> bool {
        matches!(self, Self::Funded | Self::Failing | Self::Refunding)
    }
}

/// An `addresses` row. Addresses are lowercase hex text; amounts decimal strings (`::text` casts).
#[derive(Debug, Clone, FromRow)]
pub struct AddressRow {
    pub address: String,
    pub factory: String,
    pub chain_id: i64,
    pub token: String,
    pub amount: String,
    pub expires_at: DateTime<Utc>,
    /// The canonical intent, exactly as it was stored.
    pub intent: String,
    pub terms: String,
    pub state: AddressState,
    pub balance: String,
    pub watch_id: Option<Uuid>,
    pub watch_registered_at: Option<DateTime<Utc>>,
    pub engine_job_id: Option<Uuid>,
    pub engine_submitted_at: Option<DateTime<Utc>>,
    pub execute_attempts: i32,
    pub tx_hash: Option<String>,
    pub block_number: Option<i64>,
    pub refunded_amount: Option<String>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub revert_data: Option<String>,
    pub event_seq: i64,
    pub detected_at: Option<DateTime<Utc>>,
    pub funded_at: Option<DateTime<Utc>>,
    pub settled_at: Option<DateTime<Utc>>,
    pub refunded_at: Option<DateTime<Utc>>,
    pub expired_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Columns selected for every `AddressRow` read.
pub const COLUMNS: &str = "address, factory, chain_id, token, amount::text AS amount, expires_at, intent::text AS intent, terms, \
     state, balance::text AS balance, watch_id, watch_registered_at, engine_job_id, engine_submitted_at, execute_attempts, \
     tx_hash, block_number, refunded_amount::text AS refunded_amount, failure_code, failure_message, revert_data, event_seq, \
     detected_at, funded_at, settled_at, refunded_at, expired_at, created_at, updated_at";

impl AddressRow {
    pub fn address(&self) -> Address {
        self.address.parse().expect("stored addresses are valid")
    }

    pub fn intent(&self) -> IntentJson {
        serde_json::from_str(&self.intent).expect("stored intents are canonical")
    }

    /// `PaymentFactory.execute` calldata: its selector and the stored terms.
    pub fn execute_calldata(&self) -> Bytes {
        let terms: Bytes = self.terms.parse().expect("stored terms are valid hex");
        let mut data = crate::chain::payment::IPaymentFactory::executeCall::SELECTOR.to_vec();
        data.extend_from_slice(&terms);
        data.into()
    }

    /// The calls as the payment makes them, for decoding reverts.
    pub fn calls(&self) -> Vec<Call> {
        let terms: Bytes = self.terms.parse().expect("stored terms are valid hex");
        decode_terms(&terms).map(|t| t.calls).unwrap_or_default()
    }

    pub fn resource(&self) -> ExecutableAddress {
        ExecutableAddress {
            address: self.address().to_checksum(None),
            factory: self.factory.parse::<Address>().expect("stored addresses are valid").to_checksum(None),
            intent: self.intent(),
            terms: self.terms.clone(),
        }
    }

    pub fn status(&self) -> StatusView {
        let balance = self.balance.clone();
        let status = match self.state {
            AddressState::AwaitingFunds => Status::AwaitingFunds { balance },
            AddressState::Funded => Status::Funded { balance },
            AddressState::Failing => {
                let data: Bytes = self.revert_data.as_deref().and_then(|d| d.parse().ok()).unwrap_or_default();
                Status::Failing {
                    balance,
                    message: self.failure_message.clone().unwrap_or_else(|| "execute failed".into()),
                    revert: RevertView::of_execute(&data, &self.calls()),
                }
            }
            AddressState::Settled => Status::Settled {
                transaction_hash: self.tx_hash.clone().unwrap_or_default(),
                block_number: self.block_number.unwrap_or_default().max(0) as u64,
            },
            AddressState::Refunding => Status::Refunding { balance },
            AddressState::Refunded => Status::Refunded {
                transaction_hash: self.tx_hash.clone().unwrap_or_default(),
                block_number: self.block_number.unwrap_or_default().max(0) as u64,
                amount: self.refunded_amount.clone().unwrap_or_else(|| "0".into()),
            },
            AddressState::Expired => Status::Expired { balance },
        };
        StatusView { address: self.address().to_checksum(None), status, updated_at: self.updated_at }
    }
}

/// Decodes stored terms back into `PaymentTerms` (the calls are needed to explain reverts).
fn decode_terms(terms: &[u8]) -> Option<PaymentTerms> {
    let mut data = crate::chain::payment::IPaymentFactory::executeCall::SELECTOR.to_vec();
    data.extend_from_slice(terms);
    let call = crate::chain::payment::IPaymentFactory::executeCall::abi_decode(&data).ok()?;
    Some(PaymentTerms {
        token: call.token,
        amount: call.amount,
        calls: call.calls,
        expiration_timestamp: call.expirationTimestamp,
        recovery: call.recovery,
        salt: B256::from(call.salt),
        chain_id: call.chainId.to::<u64>(),
    })
}

/// The executable address resource, served by `POST /v1/address/create` and
/// `GET /v1/address/{address}` alike.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutableAddress {
    pub address: String,
    pub factory: String,
    pub intent: IntentJson,
    /// `abi.encode(token, amount, calls, expirationTimestamp, recovery, salt, chainId)`, calls encoded:
    /// the calldata arguments of `paymentAddress` (selector `0x8809f6b6`) and `execute` (`0xc5cdfc83`).
    pub terms: String,
}

/// Where the money is. Each state carries its own fields and no others.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum Status {
    /// Waiting for `amount`; `balance` is what has arrived and been confirmed so far.
    AwaitingFunds {
        balance: String,
    },
    /// Holds `amount`; `execute` is in flight.
    Funded {
        balance: String,
    },
    /// `execute` reverts, e.g. because a call fails; retried until expiry, then refunded.
    Failing {
        balance: String,
        message: String,
        revert: RevertView,
    },
    Settled {
        transaction_hash: String,
        block_number: u64,
    },
    /// Past expiry with a balance; `execute` is returning it to `recovery`.
    Refunding {
        balance: String,
    },
    Refunded {
        transaction_hash: String,
        block_number: u64,
        amount: String,
    },
    /// Past expiry with nothing to return.
    Expired {
        balance: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    pub address: String,
    #[serde(flatten)]
    pub status: Status,
    pub updated_at: DateTime<Utc>,
}

/// Timeline event types. The app-facing ones are delivered to webhooks.
pub mod events {
    pub const CREATED: &str = "address.created";
    pub const WATCH_REGISTERED: &str = "address.watch_registered";
    pub const WATCH_LOST: &str = "address.watch_lost";
    pub const WATCH_REJECTED: &str = "address.watch_rejected";
    /// app: a payment to the address was seen at chain head (not counted until confirmed).
    pub const DETECTED: &str = "address.detected";
    pub const PAYMENT_CONFIRMED: &str = "address.payment_confirmed";
    pub const PAYMENT_ORPHANED: &str = "address.payment_orphaned";
    /// app: the address holds `amount`; execute submitted.
    pub const FUNDED: &str = "address.funded";
    pub const EXECUTE_SUBMITTED: &str = "address.execute_submitted";
    pub const EXECUTE_INCLUDED: &str = "address.execute_included";
    pub const EXECUTE_RETRIED: &str = "address.execute_retried";
    /// app: execute reverts; retried until expiry.
    pub const FAILING: &str = "address.failing";
    pub const ATTEMPT_FAILED: &str = "address.attempt_failed";
    /// app: every call ran.
    pub const SETTLED: &str = "address.settled";
    /// app: past expiry with a balance; returning it to recovery.
    pub const REFUNDING: &str = "address.refunding";
    /// app: the balance went to recovery.
    pub const REFUNDED: &str = "address.refunded";
    /// app: expired with nothing to return.
    pub const EXPIRED: &str = "address.expired";
    /// A payment to an address that has already executed; it stays there until `recover` is called.
    pub const LATE_PAYMENT: &str = "address.late_payment";
    pub const RECONCILED: &str = "address.reconciled";

    pub fn is_app_facing(event_type: &str) -> bool {
        matches!(event_type, DETECTED | FUNDED | FAILING | SETTLED | REFUNDING | REFUNDED | EXPIRED)
    }
}
