//! Every query the address lifecycle needs. A state change and the side effects it causes (watch
//! registration, execute submission, app webhooks) are committed together through the `outbox`, so
//! nothing is lost if the process dies between the two.
//!
//! Transitions are guarded by `WHERE state IN (…)` (and, for execute outcomes, by the job id) and
//! return `None` when the row was not eligible, which makes redelivered webhooks harmless.

use alloy_primitives::{Bytes, U256};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{AssertSqlSafe, PgConnection, PgPool};
use uuid::Uuid;

use super::{AddressRow, AddressState, COLUMNS, events};

// The clauses are string literals from this module, never request data.
fn select(where_clause: &str) -> AssertSqlSafe<String> {
    AssertSqlSafe(format!("SELECT {COLUMNS} FROM addresses WHERE {where_clause}"))
}

fn update(set_clause: &str, where_clause: &str) -> AssertSqlSafe<String> {
    AssertSqlSafe(format!(
        "UPDATE addresses SET {set_clause}, updated_at = now() WHERE {where_clause} RETURNING {COLUMNS}"
    ))
}

// ---------------------------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------------------------

/// A validated intent, ready to be registered.
pub struct NewAddress {
    pub address: String,
    pub factory: String,
    pub chain_id: u64,
    pub token: String,
    pub amount: U256,
    pub expires_at: DateTime<Utc>,
    /// The canonical intent, serialized: compared byte for byte with an existing registration.
    pub intent: String,
    pub terms: String,
}

pub enum CreateOutcome {
    /// First registration of this intent.
    Created(AddressRow),
    /// The same intent was registered before: the same address.
    Existing(AddressRow),
    /// The address is registered with other function signatures for the same calldata.
    Conflict(AddressRow),
}

pub async fn create(pool: &PgPool, account_id: &str, new: &NewAddress) -> Result<CreateOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let inserted: Option<AddressRow> = sqlx::query_as(AssertSqlSafe(format!(
        "INSERT INTO addresses (address, factory, chain_id, token, amount, expires_at, intent, terms)
         VALUES ($1, $2, $3, $4, CAST($5 AS numeric), $6, CAST($7 AS json), $8)
         ON CONFLICT (address) DO NOTHING
         RETURNING {COLUMNS}"
    )))
    .bind(&new.address)
    .bind(&new.factory)
    .bind(new.chain_id as i64)
    .bind(&new.token)
    .bind(new.amount.to_string())
    .bind(new.expires_at)
    .bind(&new.intent)
    .bind(&new.terms)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = match inserted {
        Some(row) => {
            link_account(&mut tx, &row.address, account_id).await?;
            let row = record_event(&mut tx, &row, events::CREATED, json!({ "account_id": account_id })).await?.0;
            enqueue(&mut tx, "register_watch", &row.address, json!({}), 0).await?;
            CreateOutcome::Created(row)
        }
        None => {
            let existing: AddressRow =
                sqlx::query_as(select("address = $1 FOR SHARE")).bind(&new.address).fetch_one(&mut *tx).await?;
            if existing.intent != new.intent {
                tx.rollback().await?;
                return Ok(CreateOutcome::Conflict(existing));
            }
            link_account(&mut tx, &existing.address, account_id).await?;
            CreateOutcome::Existing(existing)
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

async fn link_account(conn: &mut PgConnection, address: &str, account_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO address_accounts (address, account_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(address)
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------------------------

pub async fn get(pool: &PgPool, address: &str) -> Result<Option<AddressRow>, sqlx::Error> {
    sqlx::query_as(select("address = $1")).bind(address).fetch_optional(pool).await
}

// The lookups below take a connection, not the pool: webhook handlers call them inside their open
// transaction, and asking the pool for a second connection while holding one deadlocks under load.

pub async fn get_on(conn: &mut PgConnection, address: &str) -> Result<Option<AddressRow>, sqlx::Error> {
    sqlx::query_as(select("address = $1")).bind(address).fetch_optional(conn).await
}

pub async fn get_by_watch(conn: &mut PgConnection, watch_id: Uuid) -> Result<Option<AddressRow>, sqlx::Error> {
    sqlx::query_as(select("watch_id = $1")).bind(watch_id).fetch_optional(conn).await
}

/// The address an engine job was submitted for, if the job is ours.
pub async fn job_address(conn: &mut PgConnection, job_id: Uuid) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT address FROM engine_jobs WHERE job_id = $1").bind(job_id).fetch_optional(conn).await?;
    Ok(row.map(|(a,)| a))
}

/// Keyset cursor over `(created_at DESC, address DESC)` of an account's addresses.
#[derive(Debug, Clone)]
pub struct Cursor {
    pub created_at: DateTime<Utc>,
    pub address: String,
}

impl Cursor {
    pub fn encode(&self) -> String {
        format!("{}_{}", self.created_at.timestamp_micros(), self.address)
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let (micros, address) = raw.split_once('_')?;
        let created_at = DateTime::from_timestamp_micros(micros.parse().ok()?)?;
        (address.len() == 42 && address.starts_with("0x")).then(|| Self { created_at, address: address.to_owned() })
    }
}

/// An account's addresses, newest first, with the time the account created each.
pub async fn list_for_account(
    pool: &PgPool,
    account_id: &str,
    cursor: Option<&Cursor>,
    limit: i64,
) -> Result<(Vec<(AddressRow, DateTime<Utc>)>, Option<Cursor>), sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Linked {
        address: String,
        linked_at: DateTime<Utc>,
    }
    let links: Vec<Linked> = match cursor {
        Some(c) => {
            sqlx::query_as(
                "SELECT address, created_at AS linked_at FROM address_accounts
             WHERE account_id = $1 AND (created_at, address) < ($2, $3)
             ORDER BY created_at DESC, address DESC LIMIT $4",
            )
            .bind(account_id)
            .bind(c.created_at)
            .bind(&c.address)
            .bind(limit + 1)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as(
                "SELECT address, created_at AS linked_at FROM address_accounts
             WHERE account_id = $1 ORDER BY created_at DESC, address DESC LIMIT $2",
            )
            .bind(account_id)
            .bind(limit + 1)
            .fetch_all(pool)
            .await?
        }
    };
    let more = links.len() as i64 > limit;
    let links: Vec<Linked> = links.into_iter().take(limit as usize).collect();
    let addresses: Vec<String> = links.iter().map(|l| l.address.clone()).collect();
    let rows: Vec<AddressRow> = sqlx::query_as(select("address = ANY($1)")).bind(&addresses).fetch_all(pool).await?;
    let mut out = Vec::with_capacity(links.len());
    for link in &links {
        if let Some(row) = rows.iter().find(|r| r.address == link.address) {
            out.push((row.clone(), link.linked_at));
        }
    }
    let next =
        if more { links.last().map(|l| Cursor { created_at: l.linked_at, address: l.address.clone() }) } else { None };
    Ok((out, next))
}

// ---------------------------------------------------------------------------------------------
// Events and outbox
// ---------------------------------------------------------------------------------------------

/// Appends to the address's timeline and, for app-facing events, queues a webhook to every account
/// that created the address and has a webhook URL, with the address's status as it is now.
/// Returns the row with its new `event_seq`, and the event id.
pub async fn record_event(
    conn: &mut PgConnection,
    row: &AddressRow,
    event_type: &str,
    data: Value,
) -> Result<(AddressRow, Uuid), sqlx::Error> {
    let row: AddressRow = sqlx::query_as(update("event_seq = event_seq + 1", "address = $1"))
        .bind(&row.address)
        .fetch_one(&mut *conn)
        .await?;
    let id = Uuid::now_v7();
    let (created_at,): (DateTime<Utc>,) = sqlx::query_as(
        "INSERT INTO address_events (id, address, sequence, type, data) VALUES ($1, $2, $3, $4, $5) RETURNING created_at",
    )
    .bind(id)
    .bind(&row.address)
    .bind(row.event_seq)
    .bind(event_type)
    .bind(&data)
    .fetch_one(&mut *conn)
    .await?;
    metrics::counter!("execute_address_transitions_total", "event" => event_type.to_owned()).increment(1);

    if events::is_app_facing(event_type) {
        let targets: Vec<(String, String)> = sqlx::query_as(
            "SELECT a.id, a.webhook_url FROM address_accounts l JOIN accounts a ON a.id = l.account_id
             WHERE l.address = $1 AND a.webhook_url IS NOT NULL",
        )
        .bind(&row.address)
        .fetch_all(&mut *conn)
        .await?;
        if !targets.is_empty() {
            let body = serde_json::to_value(WebhookBody {
                id,
                event_type,
                created_at,
                sequence: row.event_seq,
                address: row.address().to_checksum(None),
                chain_id: row.chain_id,
                status: row.status(),
                data: data.clone(),
            })
            .expect("a webhook body serialises");
            for (account_id, url) in targets {
                enqueue(
                    &mut *conn,
                    "notify_app",
                    &row.address,
                    json!({ "url": url, "account_id": account_id, "event_id": id, "event_type": event_type, "body": body }),
                    0,
                )
                .await?;
            }
        }
    }
    Ok((row, id))
}

/// What an app webhook delivers, fields in reading order.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookBody<'a> {
    id: Uuid,
    #[serde(rename = "type")]
    event_type: &'a str,
    created_at: DateTime<Utc>,
    sequence: i64,
    address: String,
    chain_id: i64,
    status: super::StatusView,
    data: Value,
}

pub async fn enqueue(
    conn: &mut PgConnection,
    kind: &str,
    address: &str,
    payload: Value,
    delay_ms: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO outbox (id, kind, address, payload, next_attempt_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(Uuid::now_v7())
    .bind(kind)
    .bind(address)
    .bind(payload)
    .bind(delay_ms as f64 / 1000.0)
    .execute(conn)
    .await?;
    Ok(())
}

/// Queues `PaymentFactory.execute` after `delay_ms`, replacing an execute still waiting for its turn
/// (a delayed retry is superseded by a refund at expiry). Each queued execute carries its own engine
/// idempotency key, so the outbox retrying the same job never broadcasts twice.
pub async fn schedule_execute(conn: &mut PgConnection, address: &str, delay_ms: u64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM outbox WHERE address = $1 AND kind = 'submit_execute' AND dead_at IS NULL
         AND (locked_until IS NULL OR locked_until < now())",
    )
    .bind(address)
    .execute(&mut *conn)
    .await?;
    enqueue(
        conn,
        "submit_execute",
        address,
        json!({ "idempotency_key": format!("address:{address}:execute:{}", Uuid::now_v7()) }),
        delay_ms,
    )
    .await
}

/// Records an inbound webhook id. `false` means it was already processed.
pub async fn claim_inbound(conn: &mut PgConnection, source: &str, event_id: &str) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query("INSERT INTO inbound_events (source, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(source)
        .bind(event_id)
        .execute(conn)
        .await?
        .rows_affected();
    Ok(inserted == 1)
}

// ---------------------------------------------------------------------------------------------
// Watching (gum-indexer)
// ---------------------------------------------------------------------------------------------

pub async fn mark_watch_registered(
    pool: &PgPool,
    address: &str,
    watch_id: Uuid,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<AddressRow> =
        sqlx::query_as(update("watch_id = $2, watch_registered_at = now()", "address = $1 AND watch_id IS NULL"))
            .bind(address)
            .bind(watch_id)
            .fetch_optional(&mut *tx)
            .await?;
    let row = match row {
        Some(r) => Some(record_event(&mut tx, &r, events::WATCH_REGISTERED, json!({ "watch_id": watch_id })).await?.0),
        None => None,
    };
    tx.commit().await?;
    Ok(row)
}

/// gum-indexer refused to watch the address (it does not index the token, say): nothing will be
/// detected. Kept on the row for operators; the job that tried is marked dead.
pub async fn mark_watch_rejected(pool: &PgPool, address: &str, message: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<AddressRow> = sqlx::query_as(update(
        "failure_code = 'watch_rejected', failure_message = $2",
        "address = $1 AND watch_id IS NULL",
    ))
    .bind(address)
    .bind(message)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(r) = &row {
        record_event(&mut tx, r, events::WATCH_REJECTED, json!({ "message": message })).await?;
    }
    tx.commit().await
}

/// A payment was seen at chain head (not counted yet).
pub async fn apply_detected(
    conn: &mut PgConnection,
    address: &str,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update("detected_at = COALESCE(detected_at, now())", "address = $1"))
        .bind(address)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let event = match row.state {
        AddressState::AwaitingFunds | AddressState::Expired => events::DETECTED,
        AddressState::Settled | AddressState::Refunded => events::LATE_PAYMENT,
        _ => return Ok(Some(row)),
    };
    Ok(Some(record_event(conn, &row, event, data).await?.0))
}

pub async fn apply_orphaned(
    conn: &mut PgConnection,
    address: &str,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let Some(row) = get_on(&mut *conn, address).await? else { return Ok(None) };
    Ok(Some(record_event(conn, &row, events::PAYMENT_ORPHANED, data).await?.0))
}

/// A payment was confirmed; `confirmed` is the watch's new confirmed total.
pub async fn apply_confirmed(
    conn: &mut PgConnection,
    address: &str,
    confirmed: U256,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "balance = GREATEST(balance, CAST($2 AS numeric)), detected_at = COALESCE(detected_at, now())",
        "address = $1",
    ))
    .bind(address)
    .bind(confirmed.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    match row.state {
        // Nothing was there at expiry; this arrived late and goes back to recovery.
        AddressState::Expired if !confirmed.is_zero() => start_refund(conn, &row, data).await,
        AddressState::Settled | AddressState::Refunded => {
            Ok(Some(record_event(conn, &row, events::LATE_PAYMENT, data).await?.0))
        }
        _ => Ok(Some(record_event(conn, &row, events::PAYMENT_CONFIRMED, data).await?.0)),
    }
}

/// The confirmed balance reached `amount`: execute. Before expiry that settles; after, it refunds.
pub async fn apply_threshold(
    conn: &mut PgConnection,
    address: &str,
    confirmed: U256,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "balance = GREATEST(balance, CAST($2 AS numeric)), detected_at = COALESCE(detected_at, now()), \
         state = CASE WHEN expires_at >= now() THEN 'funded'::address_state ELSE 'refunding'::address_state END, \
         funded_at = CASE WHEN expires_at >= now() THEN now() ELSE funded_at END, \
         expired_at = CASE WHEN expires_at < now() THEN COALESCE(expired_at, now()) ELSE expired_at END",
        "address = $1 AND state IN ('awaiting_funds', 'expired')",
    ))
    .bind(address)
    .bind(confirmed.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(row) => {
            let event = if row.state == AddressState::Funded { events::FUNDED } else { events::REFUNDING };
            let row = record_event(conn, &row, event, data).await?.0;
            schedule_execute(conn, &row.address, 0).await?;
            Ok(Some(row))
        }
        None => {
            // Already executing or done. Funds arriving after execution stay at the address.
            let Some(row) = get_on(&mut *conn, address).await? else { return Ok(None) };
            if matches!(row.state, AddressState::Settled | AddressState::Refunded) {
                record_event(conn, &row, events::LATE_PAYMENT, data).await?;
            }
            Ok(None)
        }
    }
}

/// The watch ended (expiry plus the late-payment window).
pub async fn apply_watch_expired(
    conn: &mut PgConnection,
    address: &str,
    confirmed: U256,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> =
        sqlx::query_as(update("balance = GREATEST(balance, CAST($2 AS numeric))", "address = $1"))
            .bind(address)
            .bind(confirmed.to_string())
            .fetch_optional(&mut *conn)
            .await?;
    let Some(row) = row else { return Ok(None) };
    let has_balance = row.balance != "0";
    match row.state {
        AddressState::AwaitingFunds | AddressState::Expired if has_balance => start_refund(conn, &row, data).await,
        AddressState::AwaitingFunds => {
            let row: Option<AddressRow> = sqlx::query_as(update(
                "state = 'expired', expired_at = COALESCE(expired_at, now())",
                "address = $1 AND state = 'awaiting_funds'",
            ))
            .bind(address)
            .fetch_optional(&mut *conn)
            .await?;
            match row {
                Some(row) => Ok(Some(record_event(conn, &row, events::EXPIRED, data).await?.0)),
                None => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// Moves an address that is past expiry with a balance to `refunding`, and executes.
async fn start_refund(
    conn: &mut PgConnection,
    row: &AddressRow,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "state = 'refunding', expired_at = COALESCE(expired_at, now())",
        "address = $1 AND state IN ('awaiting_funds', 'expired', 'failing') AND engine_job_id IS NULL",
    ))
    .bind(&row.address)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let row = record_event(conn, &row, events::REFUNDING, data).await?.0;
    schedule_execute(conn, &row.address, 0).await?;
    Ok(Some(row))
}

/// Moves on every address whose expiry passed more than `margin_secs` ago and was not handled yet:
/// a balance goes back to recovery, an empty address expires. `margin_secs` lets the chain's clock
/// pass `expirationTimestamp` too, so the execute refunds rather than settles.
pub async fn expire_due(pool: &PgPool, margin_secs: u64, limit: i64) -> Result<usize, sqlx::Error> {
    let due: Vec<(String,)> = sqlx::query_as(
        "SELECT address FROM addresses
         WHERE state IN ('awaiting_funds', 'failing') AND expired_at IS NULL
           AND expires_at < now() - make_interval(secs => $1)
         ORDER BY expires_at LIMIT $2",
    )
    .bind(margin_secs as f64)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut moved = 0;
    for (address,) in due {
        let mut tx = pool.begin().await?;
        let Some(row) = sqlx::query_as::<_, AddressRow>(select("address = $1 FOR UPDATE"))
            .bind(&address)
            .fetch_optional(&mut *tx)
            .await?
        else {
            continue;
        };
        let data = json!({ "reason": "expiry passed", "expires_at": row.expires_at });
        let changed = match row.state {
            AddressState::AwaitingFunds if row.balance != "0" => start_refund(&mut tx, &row, data).await?.is_some(),
            AddressState::AwaitingFunds => {
                let r: Option<AddressRow> = sqlx::query_as(update(
                    "state = 'expired', expired_at = now()",
                    "address = $1 AND state = 'awaiting_funds'",
                ))
                .bind(&address)
                .fetch_optional(&mut *tx)
                .await?;
                match r {
                    Some(r) => {
                        record_event(&mut tx, &r, events::EXPIRED, data).await?;
                        true
                    }
                    None => false,
                }
            }
            // A retry in flight settles or refunds on its own; later attempts are refunds.
            AddressState::Failing if row.engine_job_id.is_some() => {
                sqlx::query("UPDATE addresses SET expired_at = now() WHERE address = $1")
                    .bind(&address)
                    .execute(&mut *tx)
                    .await?;
                false
            }
            AddressState::Failing => start_refund(&mut tx, &row, data).await?.is_some(),
            _ => false,
        };
        tx.commit().await?;
        moved += usize::from(changed);
    }
    Ok(moved)
}

// ---------------------------------------------------------------------------------------------
// Executing (gum-engine)
// ---------------------------------------------------------------------------------------------

pub async fn mark_execute_submitted(
    pool: &PgPool,
    address: &str,
    job_id: Uuid,
    replayed: bool,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO engine_jobs (job_id, address) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(job_id)
        .bind(address)
        .execute(&mut *tx)
        .await?;
    let row: Option<AddressRow> = sqlx::query_as(update(
        "engine_job_id = $2, engine_submitted_at = now(), \
         execute_attempts = execute_attempts + CASE WHEN engine_job_id = $2 THEN 0 ELSE 1 END",
        "address = $1 AND state IN ('funded', 'failing', 'refunding') AND (engine_job_id IS NULL OR engine_job_id = $2)",
    ))
    .bind(address)
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await?;
    let row = match row {
        Some(r) if !replayed => {
            Some(record_event(&mut tx, &r, events::EXECUTE_SUBMITTED, json!({ "engine_job_id": job_id })).await?.0)
        }
        other => other,
    };
    tx.commit().await?;
    Ok(row)
}

pub async fn apply_included(
    conn: &mut PgConnection,
    address: &str,
    job_id: Uuid,
    tx_hash: &str,
    block_number: Option<i64>,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "tx_hash = $3, block_number = COALESCE($4, block_number)",
        "address = $1 AND engine_job_id = $2",
    ))
    .bind(address)
    .bind(job_id)
    .bind(tx_hash)
    .bind(block_number)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(r) => Ok(Some(record_event(conn, &r, events::EXECUTE_INCLUDED, data).await?.0)),
        None => Ok(None),
    }
}

pub async fn apply_settled(
    conn: &mut PgConnection,
    address: &str,
    job_id: Uuid,
    tx_hash: &str,
    block_number: Option<i64>,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "state = 'settled', settled_at = now(), tx_hash = $3, block_number = COALESCE($4, block_number), engine_job_id = NULL, \
         failure_code = NULL, failure_message = NULL, revert_data = NULL",
        "address = $1 AND engine_job_id = $2 AND state IN ('funded', 'failing', 'refunding')",
    ))
    .bind(address)
    .bind(job_id)
    .bind(tx_hash)
    .bind(block_number)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(r) => Ok(Some(record_event(conn, &r, events::SETTLED, data).await?.0)),
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_refunded(
    conn: &mut PgConnection,
    address: &str,
    job_id: Uuid,
    tx_hash: &str,
    block_number: Option<i64>,
    amount: U256,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "state = 'refunded', refunded_at = now(), tx_hash = $3, block_number = COALESCE($4, block_number), \
         refunded_amount = CAST($5 AS numeric), engine_job_id = NULL, expired_at = COALESCE(expired_at, now()), \
         failure_code = NULL, failure_message = NULL, revert_data = NULL",
        "address = $1 AND engine_job_id = $2 AND state IN ('funded', 'failing', 'refunding')",
    ))
    .bind(address)
    .bind(job_id)
    .bind(tx_hash)
    .bind(block_number)
    .bind(amount.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(r) => Ok(Some(record_event(conn, &r, events::REFUNDED, data).await?.0)),
        None => Ok(None),
    }
}

/// Why an execute attempt failed.
#[derive(Debug)]
pub struct Failure {
    pub code: String,
    pub message: String,
    pub revert_data: Option<Bytes>,
}

/// An execute attempt failed: the address is `failing`, and, when `retry_in_ms` is set, tried again
/// after that long. `job_id` is `None` when gum-engine refused the submission itself.
pub async fn apply_attempt_failed(
    conn: &mut PgConnection,
    address: &str,
    job_id: Option<Uuid>,
    failure: &Failure,
    retry_in_ms: Option<u64>,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let before: Option<(AddressState,)> = sqlx::query_as("SELECT state FROM addresses WHERE address = $1")
        .bind(address)
        .fetch_optional(&mut *conn)
        .await?;
    let row: Option<AddressRow> = sqlx::query_as(update(
        "state = 'failing', engine_job_id = NULL, failure_code = $3, failure_message = $4, revert_data = $5",
        "address = $1 AND engine_job_id IS NOT DISTINCT FROM $2 AND state IN ('funded', 'failing', 'refunding')",
    ))
    .bind(address)
    .bind(job_id)
    .bind(&failure.code)
    .bind(&failure.message)
    .bind(failure.revert_data.as_ref().map(ToString::to_string))
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let mut data = data;
    data["code"] = json!(failure.code);
    data["message"] = json!(failure.message);
    let event =
        if before.is_some_and(|(s,)| s != AddressState::Failing) { events::FAILING } else { events::ATTEMPT_FAILED };
    let row = record_event(conn, &row, event, data).await?.0;
    if let Some(delay) = retry_in_ms {
        schedule_execute(conn, &row.address, delay).await?;
    }
    Ok(Some(row))
}

/// gum-engine gave up on a job before it executed (it expired in the mempool, say): the state stays
/// as it is, and a new execute is queued after `retry_in_ms`.
pub async fn retry_execute(
    conn: &mut PgConnection,
    address: &str,
    job_id: Uuid,
    retry_in_ms: u64,
    data: Value,
) -> Result<Option<AddressRow>, sqlx::Error> {
    let row: Option<AddressRow> = sqlx::query_as(update(
        "engine_job_id = NULL",
        "address = $1 AND engine_job_id = $2 AND state IN ('funded', 'failing', 'refunding')",
    ))
    .bind(address)
    .bind(job_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let row = record_event(conn, &row, events::EXECUTE_RETRIED, data).await?.0;
    schedule_execute(conn, &row.address, retry_in_ms).await?;
    Ok(Some(row))
}

/// Operator retry of a `failing` address whose automatic retries stopped.
pub async fn retry_failing(pool: &PgPool, address: &str) -> Result<Option<AddressRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<AddressRow> =
        sqlx::query_as(select("address = $1 AND state = 'failing' AND engine_job_id IS NULL FOR UPDATE"))
            .bind(address)
            .fetch_optional(&mut *tx)
            .await?;
    let row = match row {
        Some(r) => {
            let r = record_event(&mut tx, &r, events::EXECUTE_RETRIED, json!({ "operator": true })).await?.0;
            schedule_execute(&mut tx, &r.address, 0).await?;
            Some(r)
        }
        None => None,
    };
    tx.commit().await?;
    Ok(row)
}

// ---------------------------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------------------------

/// Addresses awaiting funds with a watch that have been quiet for `stale_secs`.
pub async fn stale_open(pool: &PgPool, stale_secs: i64, limit: i64) -> Result<Vec<AddressRow>, sqlx::Error> {
    sqlx::query_as(select(
        "state IN ('awaiting_funds', 'expired') AND watch_id IS NOT NULL \
         AND expires_at > now() - make_interval(secs => 172800) \
         AND updated_at < now() - make_interval(secs => $1) ORDER BY updated_at LIMIT $2",
    ))
    .bind(stale_secs as f64)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Addresses with an execute job submitted more than `stale_secs` ago and untouched for `repoll_secs`.
pub async fn stale_in_flight(
    pool: &PgPool,
    stale_secs: i64,
    repoll_secs: i64,
    limit: i64,
) -> Result<Vec<AddressRow>, sqlx::Error> {
    sqlx::query_as(select(
        "engine_job_id IS NOT NULL AND engine_submitted_at < now() - make_interval(secs => $1) \
         AND updated_at < now() - make_interval(secs => $2) ORDER BY updated_at LIMIT $3",
    ))
    .bind(stale_secs as f64)
    .bind(repoll_secs as f64)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// How many addresses have an execute in flight, and how long ago the oldest was submitted.
pub async fn in_flight_backlog(pool: &PgPool) -> Result<(i64, f64), sqlx::Error> {
    sqlx::query_as(
        "SELECT count(*), COALESCE(EXTRACT(EPOCH FROM now() - min(engine_submitted_at))::float8, 0) \
         FROM addresses WHERE engine_job_id IS NOT NULL",
    )
    .fetch_one(pool)
    .await
}

/// How many outbox jobs are due, and how long the oldest has been due.
pub async fn outbox_due(pool: &PgPool) -> Result<(i64, f64), sqlx::Error> {
    sqlx::query_as(
        "SELECT count(*), COALESCE(EXTRACT(EPOCH FROM now() - min(next_attempt_at))::float8, 0) \
         FROM outbox WHERE dead_at IS NULL AND next_attempt_at <= now()",
    )
    .fetch_one(pool)
    .await
}

/// Bumps `updated_at` so the reconciler does not re-check the row every tick.
pub async fn touch(pool: &PgPool, address: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE addresses SET updated_at = now() WHERE address = $1").bind(address).execute(pool).await?;
    Ok(())
}

/// Forgets a watch gum-indexer no longer knows and queues a fresh registration.
pub async fn reregister_watch(pool: &PgPool, address: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<AddressRow> = sqlx::query_as(update(
        "watch_id = NULL, watch_registered_at = NULL",
        "address = $1 AND state IN ('awaiting_funds', 'expired')",
    ))
    .bind(address)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(r) = &row {
        record_event(&mut tx, r, events::WATCH_LOST, json!({})).await?;
        enqueue(&mut tx, "register_watch", &r.address, json!({}), 0).await?;
    }
    tx.commit().await?;
    Ok(row.is_some())
}

pub async fn prune(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM inbound_events WHERE received_at < now() - interval '7 days'").execute(pool).await?;
    Ok(())
}
