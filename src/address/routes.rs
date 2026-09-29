//! `POST /v1/address/create`, `GET /v1/address/{address}`, `GET /v1/address/{address}/status` and
//! `GET /v1/chains`.

use alloy_primitives::Address;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use super::store::{self, CreateOutcome, NewAddress};
use crate::auth::AppCaller;
use crate::error::{ApiError, Issue};
use crate::intent::{self, Rules, abi_json};
use crate::state::AppState;

/// Registers an intent and returns its executable address. The response depends on the body alone:
/// the same intent always gives the same address and the same `200`, however many times it is sent.
pub async fn create(
    State(state): State<AppState>,
    caller: AppCaller,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body?;
    let cfg = &state.config.addresses;
    let rules = Rules {
        registry: &state.registry,
        factory: state.factory,
        now: Utc::now().timestamp().max(0) as u64,
        min_expiry_lead_secs: cfg.min_expiry_lead_secs,
        max_expiry_lead_secs: cfg.max_expiry_lead_secs,
    };
    let intent = intent::parse(&body, &rules).map_err(ApiError::invalid_intent)?;
    let terms = intent.terms();
    let address = terms.payment_address(state.factory);
    let canonical = intent.to_json();
    let new = NewAddress {
        address: format!("{address:#x}"),
        factory: format!("{:#x}", state.factory),
        chain_id: intent.chain_id,
        token: format!("{:#x}", intent.token),
        amount: intent.amount,
        expires_at: DateTime::<Utc>::from_timestamp(intent.expiration_timestamp as i64, 0)
            .expect("bounded by the rules"),
        intent: serde_json::to_string(&canonical).expect("an intent serialises"),
        terms: terms.terms().to_string(),
    };

    match store::create(&state.pool, &caller.account_id, &new).await? {
        CreateOutcome::Created(row) => {
            metrics::counter!("execute_addresses_created_total", "chain" => intent.chain_id.to_string(), "credential" => caller.credential.as_str())
                .increment(1);
            state.outbox_wake.notify_one();
            tracing::info!(address = %row.address, account_id = %caller.account_id, credential = caller.credential.as_str(), chain_id = intent.chain_id, "address created");
            Ok(Json(row.resource()).into_response())
        }
        CreateOutcome::Existing(row) => Ok(Json(row.resource()).into_response()),
        CreateOutcome::Conflict(existing) => {
            let theirs = existing.intent();
            let differing = canonical
                .calls
                .iter()
                .zip(&theirs.calls)
                .position(|(ours, theirs)| ours.function != theirs.function)
                .unwrap_or(0);
            Err(ApiError::conflict(
                "address_conflict",
                format!(
                    "{} is already registered with call {differing} as \"{}\": the same calldata cannot carry two signatures; use another salt for yours",
                    address.to_checksum(None),
                    theirs.calls.get(differing).map_or("", |c| c.function.as_str()),
                ),
            ))
        }
    }
}

fn path_address(raw: &str) -> Result<Address, ApiError> {
    let mut issues = Vec::new();
    abi_json::address(&Value::String(raw.to_owned()), "", &mut issues).ok_or_else(|| {
        ApiError::invalid_body(
            issues.into_iter().map(|i| Issue::new("", format!("address in the path: {}", i.message))).collect(),
        )
    })
}

/// The executable address and the intent it encodes. An address's intent never changes, so the
/// response may be cached forever; a `404` may not (the address could be created a moment later).
pub async fn lookup(State(state): State<AppState>, Path(raw): Path<String>) -> Result<Response, ApiError> {
    let address = path_address(&raw)?;
    let row = store::get(&state.pool, &format!("{address:#x}")).await?;
    let Some(row) = row else {
        return Err(ApiError::not_found("Execute has no intent for this address"));
    };
    let mut response = Json(row.resource()).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
    Ok(response)
}

/// Where the money is now.
pub async fn status(State(state): State<AppState>, Path(raw): Path<String>) -> Result<Response, ApiError> {
    let address = path_address(&raw)?;
    let Some(row) = store::get(&state.pool, &format!("{address:#x}")).await? else {
        return Err(ApiError::not_found("Execute has no intent for this address"));
    };
    let mut response = Json(row.status()).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Serialize)]
pub struct ChainsView {
    pub factory: String,
    pub chains: Vec<ChainView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainView {
    pub chain_id: u64,
    pub name: String,
    pub tokens: Vec<TokenView>,
}

#[derive(Serialize)]
pub struct TokenView {
    pub symbol: String,
    pub address: String,
    pub decimals: u8,
}

/// The chains Execute is live on, the tokens an address may be funded with on each, and the factory.
pub async fn chains(State(state): State<AppState>) -> Json<ChainsView> {
    let chains = state
        .registry
        .chains()
        .map(|c| ChainView {
            chain_id: c.chain_id,
            name: c.name.clone(),
            tokens: c
                .tokens
                .iter()
                .map(|t| TokenView {
                    symbol: t.symbol.clone(),
                    address: t.address.to_checksum(None),
                    decimals: t.decimals,
                })
                .collect(),
        })
        .collect();
    Json(ChainsView { factory: state.factory.to_checksum(None), chains })
}
