//! End-to-end tests over HTTP against a real Postgres, with gum-indexer, gum-engine and an app's
//! webhook stubbed by wiremock. Run with `TEST_DATABASE_URL=postgres://…` (see README).

mod common;

use std::time::Duration;

use common::{
    ENGINE_SECRET, Harness, INDEXER_SECRET, USDC, USER, VAULT, engine_event, indexer_event, intent, recovered_receipt,
    settled_receipt,
};
use execute_server::reconciler;
use serde_json::{Value, json};

macro_rules! harness {
    () => {
        match Harness::start().await {
            Some(h) => h,
            None => {
                eprintln!("TEST_DATABASE_URL not set; skipping");
                return;
            }
        }
    };
}

#[tokio::test]
async fn the_same_intent_gives_the_same_address_and_lookup_serves_it_back() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    let body = intent(120);

    let first = h.create(&key, &body).await;
    assert_eq!(first.status(), 200);
    let created: Value = first.json().await.unwrap();
    let address = created["address"].as_str().unwrap().to_owned();
    assert_eq!(created["intent"], body, "the intent is echoed exactly");
    assert_eq!(created["factory"], common::FACTORY);
    assert!(
        created["terms"]
            .as_str()
            .unwrap()
            .starts_with("0x000000000000000000000000e7f1725e7734ce288f8367e1bb143e90bb3f0512")
    );

    // Again: same body, same address, same 200, no second watch.
    let again: Value = h.create(&key, &body).await.json().await.unwrap();
    assert_eq!(again, created);

    // Anyone can look it up, by any case of the address, and cache it forever.
    let lookup = h.http.get(h.url(&format!("/v1/address/{}", address.to_lowercase()))).send().await.unwrap();
    assert_eq!(lookup.status(), 200);
    assert_eq!(lookup.headers()["cache-control"], "public, max-age=31536000, immutable");
    assert_eq!(lookup.headers()["access-control-allow-origin"], "*");
    assert_eq!(lookup.json::<Value>().await.unwrap(), created);

    let status = h.status(&address).await;
    assert_eq!(status["state"], "awaiting_funds");
    assert_eq!(status["balance"], "0");
    assert_eq!(status["address"], address);

    let unknown = h.http.get(h.url("/v1/address/0x0000000000000000000000000000000000000abc")).send().await.unwrap();
    assert_eq!(unknown.status(), 404);
    assert_eq!(unknown.json::<Value>().await.unwrap()["error"]["issues"], json!([]));
    let bad = h.http.get(h.url("/v1/address/0xnope")).send().await.unwrap();
    assert_eq!(bad.status(), 400);

    // One watch, registered once, past expiry by the late-payment window.
    let watches = h
        .wait_for("watch registration", Duration::from_secs(5), || async {
            let reqs = h.indexer.received_requests().await.unwrap_or_default();
            (!reqs.is_empty()).then_some(reqs)
        })
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.indexer.received_requests().await.unwrap().len(), 1);
    let watch: Value = serde_json::from_slice(&watches[0].body).unwrap();
    assert_eq!(watch["payment_address"], address.to_lowercase());
    assert_eq!(watch["token"], USDC.to_lowercase());
    assert_eq!(watch["balance_threshold"], "100000000");
    assert_eq!(watch["chain"], "31337");
}

#[tokio::test]
async fn an_invalid_intent_lists_every_problem_with_what_to_send() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    let mut body = intent(120);
    body["amount"] = json!(100000000);
    body["chainId"] = json!("31337");
    body["calls"][1]["function"] = json!("function deposit(uint256 assets, address receiver) returns (uint256)");
    body["calls"][0]["data"] = json!("0x");
    let res = h.create(&key, &body).await;
    assert_eq!(res.status(), 400);
    let err: Value = res.json().await.unwrap();
    assert_eq!(err["error"]["code"], "invalid_intent");
    let paths: Vec<&str> =
        err["error"]["issues"].as_array().unwrap().iter().map(|i| i["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/amount", "/calls/0/data", "/calls/1/function", "/chainId"]);

    let not_json = h
        .http
        .post(h.url("/v1/address/create"))
        .bearer_auth(&key)
        .body("{")
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(not_json.status(), 400);
    assert_eq!(not_json.json::<Value>().await.unwrap()["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn one_calldata_cannot_carry_two_signatures() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    let body = intent(120);
    assert_eq!(h.create(&key, &body).await.status(), 200);
    let mut relabelled = body.clone();
    relabelled["calls"][1]["function"] = json!("deposit(uint256 assets, address beneficiary)");
    let res = h.create(&key, &relabelled).await;
    assert_eq!(res.status(), 409);
    let err: Value = res.json().await.unwrap();
    assert_eq!(err["error"]["code"], "address_conflict");
    assert!(
        err["error"]["message"].as_str().unwrap().contains("call 1 as \"deposit(uint256 assets, address receiver)\"")
    );
}

#[tokio::test]
async fn api_keys_are_for_servers_and_client_ids_for_allowed_origins() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    let account = h.account("did:privy:alice").await;
    let client_id = account["clientId"].as_str().unwrap().to_owned();
    assert!(client_id.starts_with("exe_client_"));
    let create = |headers: Vec<(&'static str, String)>| {
        let mut req = h.http.post(h.url("/v1/address/create")).json(&intent(120));
        for (k, v) in headers {
            req = req.header(k, v);
        }
        async move {
            let res = req.send().await.unwrap();
            let status = res.status().as_u16();
            (status, res.json::<Value>().await.unwrap())
        }
    };

    // A secret key sent from a web page is refused.
    let (status, body) =
        create(vec![("authorization", format!("Bearer {key}")), ("origin", "https://app.example.com".into())]).await;
    assert_eq!((status, body["error"]["code"].as_str().unwrap()), (403, "api_key_in_browser"));

    // A client ID needs a browser's Origin, and an allowed one.
    let (status, body) = create(vec![("x-client-id", client_id.clone())]).await;
    assert_eq!((status, body["error"]["code"].as_str().unwrap()), (403, "origin_required"));
    let (status, body) =
        create(vec![("x-client-id", client_id.clone()), ("origin", "https://app.example.com".into())]).await;
    assert_eq!((status, body["error"]["code"].as_str().unwrap()), (403, "origin_not_allowed"));

    let token = h.privy_token("did:privy:alice");
    let res = h
        .http
        .put(h.url("/v1/account/allowed-origins"))
        .bearer_auth(&token)
        .json(&json!({ "allowedOrigins": ["https://App.example.com", "http://evil.example.com"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let issues = res.json::<Value>().await.unwrap()["error"]["issues"].clone();
    assert_eq!(issues[0]["message"], "write it as \"https://app.example.com\"");
    assert_eq!(issues[1]["path"], "/allowedOrigins/1");
    let res = h
        .http
        .put(h.url("/v1/account/allowed-origins"))
        .bearer_auth(&token)
        .json(&json!({ "allowedOrigins": ["https://app.example.com", "https://*.preview.example.com"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let (status, created) =
        create(vec![("x-client-id", client_id.clone()), ("origin", "https://app.example.com".into())]).await;
    assert_eq!(status, 200, "{created}");
    let (status, _) =
        create(vec![("x-client-id", client_id.clone()), ("origin", "https://pr-7.preview.example.com".into())]).await;
    assert_eq!(status, 200);
    let (status, _) =
        create(vec![("x-client-id", client_id.clone()), ("origin", "https://preview.example.com".into())]).await;
    assert_eq!(status, 403);

    // One credential at a time; dashboard sessions cannot create.
    let (status, _) =
        create(vec![("authorization", format!("Bearer {key}")), ("x-client-id", client_id.clone())]).await;
    assert_eq!(status, 400);
    let (status, _) = create(vec![("authorization", format!("Bearer {token}"))]).await;
    assert_eq!(status, 401);
    let (status, _) = create(vec![]).await;
    assert_eq!(status, 401);
    let (status, _) = create(vec![("authorization", "Bearer exe_sk_wrong".into())]).await;
    assert_eq!(status, 401);

    // And API keys cannot manage the account.
    let res = h.http.get(h.url("/v1/account")).bearer_auth(&key).send().await.unwrap();
    assert_eq!(res.status(), 403);

    // Browsers may call the public API from anywhere: preflight passes, the origin check is ours.
    let preflight = h
        .http
        .request(reqwest::Method::OPTIONS, h.url("/v1/address/create"))
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type, x-client-id")
        .send()
        .await
        .unwrap();
    assert_eq!(preflight.status(), 204);
    assert_eq!(preflight.headers()["access-control-allow-headers"], "content-type, x-client-id");
    // The dashboard routes send no CORS headers.
    let res = h
        .http
        .get(h.url("/v1/account"))
        .bearer_auth(&token)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert!(res.headers().get("access-control-allow-origin").is_none());

    // Rotating the client ID retires the old one.
    let rotated: Value = h
        .http
        .post(h.url("/v1/account/client-id/rotate"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(rotated["clientId"], client_id);
    let (status, _) = create(vec![("x-client-id", client_id), ("origin", "https://app.example.com".into())]).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn account_routes_manage_the_key_webhook_and_list_addresses() {
    let h = harness!();
    let token = h.privy_token("did:privy:bob");
    let account = h.account("did:privy:bob").await;
    assert_eq!(account["apiKey"], Value::Null);
    assert!(account["webhookSecret"].as_str().unwrap().starts_with("whsec_"));

    let key = h.api_key("did:privy:bob").await;
    let again = h.http.post(h.url("/v1/account/api-key")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(again.status(), 409);
    let rotated: Value = h
        .http
        .post(h.url("/v1/account/api-key/rotate"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_key = rotated["apiKey"].as_str().unwrap();
    assert_eq!(h.create(&key, &intent(120)).await.status(), 401, "the old key stops working");
    assert_eq!(h.create(new_key, &intent(120)).await.status(), 200);

    let res = h
        .http
        .put(h.url("/v1/account/webhook-url"))
        .bearer_auth(&token)
        .json(&json!({ "webhookUrl": "ftp://x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    h.set_webhook("did:privy:bob").await;
    let cleared: Value =
        h.http.delete(h.url("/v1/account/webhook-url")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(cleared["webhookUrl"], Value::Null);

    let list: Value = h
        .http
        .get(h.url("/v1/account/addresses?limit=10"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["status"]["state"], "awaiting_funds");
    assert_eq!(
        items[0]["functions"],
        json!(["approve(address spender, uint256 amount)", "deposit(uint256 assets, address receiver)"])
    );
    assert_eq!(list["nextCursor"], Value::Null);
}

/// Funded before expiry: executed, settled, and the app told at every step.
#[tokio::test]
async fn a_funded_address_executes_and_settles() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    h.set_webhook("did:privy:alice").await;
    let secret = h.account("did:privy:alice").await["webhookSecret"].as_str().unwrap().to_owned();
    let created: Value = h.create(&key, &intent(120)).await.json().await.unwrap();
    let address = created["address"].as_str().unwrap().to_owned();
    let lower = address.to_lowercase();

    assert_eq!(
        h.deliver("/v1/webhooks/indexer", INDEXER_SECRET, &indexer_event("i1", "payment.pending", &lower, "0"))
            .await
            .status(),
        200
    );
    assert_eq!(
        h.deliver(
            "/v1/webhooks/indexer",
            INDEXER_SECRET,
            &indexer_event("i2", "threshold.reached", &lower, "100000000")
        )
        .await
        .status(),
        200
    );
    // Redelivery is harmless.
    assert_eq!(
        h.deliver(
            "/v1/webhooks/indexer",
            INDEXER_SECRET,
            &indexer_event("i2", "threshold.reached", &lower, "100000000")
        )
        .await
        .status(),
        200
    );
    assert_eq!(h.status(&address).await["state"], "funded");

    let job = h.engine_job(1).await;
    let submission: Value = serde_json::from_slice(&h.engine.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(submission["to"], common::FACTORY.to_lowercase());
    assert!(submission["data"].as_str().unwrap().starts_with("0xc5cdfc83"), "PaymentFactory.execute");
    assert_eq!(&submission["data"].as_str().unwrap()[10..], &created["terms"].as_str().unwrap()[2..], "execute(terms)");

    let confirmed = engine_event(
        "e1",
        "transaction.confirmed",
        &job,
        Some("success"),
        Some(settled_receipt(&lower, 100_000_000)),
        None,
    );
    assert_eq!(h.deliver("/v1/webhooks/engine", ENGINE_SECRET, &confirmed).await.status(), 200);
    let status = h.status(&address).await;
    assert_eq!(status["state"], "settled");
    assert_eq!(status["transactionHash"], format!("0x{}", "cd".repeat(32)));
    assert_eq!(status["blockNumber"], 9);

    let deliveries = h
        .wait_for("app webhooks", Duration::from_secs(5), || async {
            let d = h.app_deliveries(&secret).await;
            (d.len() >= 3).then_some(d)
        })
        .await;
    let types: Vec<&str> = deliveries.iter().map(|d| d["type"].as_str().unwrap()).collect();
    assert_eq!(types, ["address.detected", "address.funded", "address.settled"]);
    assert_eq!(deliveries[2]["status"]["state"], "settled");
    assert_eq!(deliveries[2]["address"], address);
}

/// `CallFailed(1, Error("vault is full"))`, as `PaymentFactory.execute` reverts when call 1 does.
const VAULT_FULL: &str = "0x5c0dee5d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006408c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d7661756c742069732066756c6c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// gum-engine's report of a simulation that reverted with `revert`: nothing was sent.
fn simulation_reverted(event_id: &str, job: &str, revert: &str) -> Value {
    let mut event = engine_event(
        event_id,
        "transaction.failed",
        job,
        None,
        None,
        Some(json!({ "code": "simulation_reverted", "message": "execution reverted", "revert_data": revert })),
    );
    event["tx_hash"] = Value::Null;
    event
}

/// The calls revert: failing. At expiry the next execute returns the balance to recovery.
#[tokio::test]
async fn a_failing_address_is_refunded_at_expiry() {
    // Retries far apart, so none is in flight when the address expires.
    let Some(h) = Harness::start_with(|c| {
        c.addresses.execute_retry_base_ms = 60_000;
        c.addresses.execute_retry_cap_ms = 60_000;
    })
    .await
    else {
        return;
    };
    let key = h.api_key("did:privy:alice").await;
    let created: Value = h.create(&key, &intent(3)).await.json().await.unwrap();
    let address = created["address"].as_str().unwrap().to_owned();
    let lower = address.to_lowercase();

    h.deliver("/v1/webhooks/indexer", INDEXER_SECRET, &indexer_event("i1", "threshold.reached", &lower, "100000000"))
        .await;
    let job = h.engine_job(1).await;
    assert_eq!(
        h.deliver("/v1/webhooks/engine", ENGINE_SECRET, &simulation_reverted("e1", &job, VAULT_FULL)).await.status(),
        200
    );
    let status = h.status(&address).await;
    assert_eq!(status["state"], "failing");
    assert_eq!(status["balance"], "100000000");
    assert_eq!(status["revert"]["name"], "CallFailed");
    assert_eq!(status["revert"]["call"]["index"], 1);
    assert_eq!(status["revert"]["reason"]["args"]["message"], "vault is full");
    assert!(status["message"].as_str().unwrap().contains("vault is full"));

    tokio::time::sleep(Duration::from_secs(4)).await;
    reconciler::expire(&h.state).await.unwrap();
    assert_eq!(h.status(&address).await["state"], "refunding");
    // The refund does not wait for the minute-long retry: it replaces it.
    let refund = h.engine_job(2).await;
    assert_ne!(refund, job);
    h.deliver(
        "/v1/webhooks/engine",
        ENGINE_SECRET,
        &engine_event(
            "e2",
            "transaction.confirmed",
            &refund,
            Some("success"),
            Some(recovered_receipt(&lower, 100_000_000)),
            None,
        ),
    )
    .await;
    let status = h.status(&address).await;
    assert_eq!(status["state"], "refunded");
    assert_eq!(status["amount"], "100000000");
}

/// A retry already in flight at expiry is left to finish: landing after expiry, it refunds.
#[tokio::test]
async fn a_retry_in_flight_at_expiry_refunds_on_its_own() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    let created: Value = h.create(&key, &intent(2)).await.json().await.unwrap();
    let address = created["address"].as_str().unwrap().to_owned();
    let lower = address.to_lowercase();

    h.deliver("/v1/webhooks/indexer", INDEXER_SECRET, &indexer_event("i1", "threshold.reached", &lower, "100000000"))
        .await;
    let job = h.engine_job(1).await;
    h.deliver("/v1/webhooks/engine", ENGINE_SECRET, &simulation_reverted("e1", &job, VAULT_FULL)).await;
    let retry = h.engine_job(2).await;
    assert_eq!(h.status(&address).await["state"], "failing");

    tokio::time::sleep(Duration::from_secs(3)).await;
    reconciler::expire(&h.state).await.unwrap();
    assert_eq!(h.status(&address).await["state"], "failing", "the retry in flight decides");
    h.deliver(
        "/v1/webhooks/engine",
        ENGINE_SECRET,
        &engine_event(
            "e2",
            "transaction.confirmed",
            &retry,
            Some("success"),
            Some(recovered_receipt(&lower, 100_000_000)),
            None,
        ),
    )
    .await;
    assert_eq!(h.status(&address).await["state"], "refunded");
}

/// Nothing arrived by expiry: expired. A late payment is still seen, and refunded.
#[tokio::test]
async fn an_unfunded_address_expires_and_a_late_payment_is_refunded() {
    let h = harness!();
    let key = h.api_key("did:privy:alice").await;
    h.set_webhook("did:privy:alice").await;
    let secret = h.account("did:privy:alice").await["webhookSecret"].as_str().unwrap().to_owned();
    let created: Value = h.create(&key, &intent(2)).await.json().await.unwrap();
    let address = created["address"].as_str().unwrap().to_owned();
    let lower = address.to_lowercase();

    tokio::time::sleep(Duration::from_secs(3)).await;
    reconciler::expire(&h.state).await.unwrap();
    assert_eq!(h.status(&address).await["state"], "expired");

    // The watch outlives the expiry: a late payment is refunded.
    h.deliver("/v1/webhooks/indexer", INDEXER_SECRET, &indexer_event("i1", "payment.confirmed", &lower, "5000000"))
        .await;
    assert_eq!(h.status(&address).await["state"], "refunding");
    let job = h.engine_job(1).await;
    h.deliver(
        "/v1/webhooks/engine",
        ENGINE_SECRET,
        &engine_event(
            "e1",
            "transaction.confirmed",
            &job,
            Some("success"),
            Some(recovered_receipt(&lower, 5_000_000)),
            None,
        ),
    )
    .await;
    assert_eq!(h.status(&address).await["state"], "refunded");

    let deliveries = h
        .wait_for("app webhooks", Duration::from_secs(5), || async {
            let d = h.app_deliveries(&secret).await;
            (d.len() >= 3).then_some(d)
        })
        .await;
    let types: Vec<&str> = deliveries.iter().map(|d| d["type"].as_str().unwrap()).collect();
    assert_eq!(types, ["address.expired", "address.refunding", "address.refunded"]);
}

/// Engine events are verified, and an unknown recent job is retried rather than lost.
#[tokio::test]
async fn inbound_webhooks_are_verified() {
    let h = harness!();
    let body = indexer_event("i1", "payment.pending", "0x0000000000000000000000000000000000000001", "0");
    assert_eq!(h.deliver("/v1/webhooks/indexer", "wrong-secret", &body).await.status(), 401);
    assert_eq!(
        h.deliver("/v1/webhooks/indexer", INDEXER_SECRET, &body).await.status(),
        200,
        "unknown address: acknowledged"
    );
    let job = common::job_id(99);
    let event = engine_event("e1", "transaction.confirmed", &job, Some("success"), None, None);
    assert_eq!(
        h.deliver("/v1/webhooks/engine", ENGINE_SECRET, &event).await.status(),
        503,
        "a job not recorded yet is retried"
    );
    let _ = (USER, VAULT);
}
