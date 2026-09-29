# execute-server

The Execute API (api.execute.cash). An app posts an **execution intent** and gets back its **executable
address**. Anyone can look the address up and get the intent back. Once the address holds the intent's
amount, Execute executes it. Rust (axum, sqlx, Postgres), deployed on Railway.

Every blockchain interaction is delegated. [gum-indexer](../gum-indexer) watches addresses,
[gum-engine](../gum-engine) sends `PaymentFactory.execute`, and both call back into this service. The
contracts are [gum-contracts](../gum-contracts)' `PaymentFactory` and `Payment`. execute-server itself
never opens an RPC connection, so creating an address is a CREATE2 computation and one database
transaction. The design rationale is in [execute-cash/design/api.md](../execute-cash/design/api.md).

```
app ──POST /v1/address/create──▶ execute-server ──(outbox)──▶ gum-indexer  POST /v1/watches
wallet ──GET /v1/address/{a}──▶    │  ◀──── webhook ─────────┘   payment.* / threshold.reached / watch.expired
                                   ├──(outbox)──▶ gum-engine   POST /v1/transactions  PaymentFactory.execute
                                   │  ◀──── webhook ─────────┘   transaction.included / confirmed / failed
                                   └──(outbox)──▶ app webhooks   address.funded / settled / failing / refunded …
```

## API

```
POST /v1/address/create            intent → executable address       API key or client ID
GET  /v1/address/{address}         executable address → intent       public, immutable
GET  /v1/address/{address}/status  where the money is now            public
GET  /v1/chains                    chains, tokens, factory           public
```

The API has four conventions:

- Keys are camelCase.
- Every field is required, and unknown fields are rejected.
- Each value has exactly one JSON spelling.
- Errors are `{"error":{"code","message","issues":[{"path","message"}]}}`. `issues` lists every
  invalid field at once, each with a JSON Pointer, and is `[]` for errors that aren't about a field.

### Create

```http
POST /v1/address/create
Authorization: Bearer exe_sk_…
Content-Type: application/json

{
  "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "amount": "1000000000",
  "calls": [
    { "target": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "function": "approve(address spender, uint256 amount)",
      "args": ["0xbeef0e0834849aCC03f0089F01f4F1Eeb06873C9", "1000000000"] },
    { "target": "0xbeef0e0834849aCC03f0089F01f4F1Eeb06873C9",
      "function": "deposit(uint256 assets, address receiver)",
      "args": ["1000000000", "0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086"] }
  ],
  "expirationTimestamp": 1800000000,
  "recovery": "0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086",
  "salt": "0x4b7ef6dd50ef7570851a0abfbf121fa35edfcdd5f83d07e6bc275547447ec004",
  "chainId": 8453
}
```

| Field | JSON | |
|---|---|---|
| `token` | address | A token `GET /v1/chains` lists for the chain: USDC, USDT (USDT0) or AUSD today. |
| `amount` | base-10 string | Exactly what the calls spend, in base units. |
| `calls` | `[{target, function, args}]`, at least one | Run in order, as the address. `function` is the signature with parameter names, e.g. `deposit(uint256 assets, address receiver)`, written exactly in canonical form. `args` are positional, in the values' JSON forms. The server does the ABI encoding: raw calldata is not accepted. |
| `expirationTimestamp` | integer, unix seconds | 1 minute to 5 minutes from now (`addresses.min/max_expiry_lead_secs`). |
| `recovery` | address | Receives the excess, everything after expiry, and late payments. |
| `salt` | 32 bytes, lowercase hex | Choose one per payment, e.g. random, or `keccak256(orderId)`. |
| `chainId` | integer | A chain `GET /v1/chains` lists. |

Each type has one JSON form:

- **Addresses:** all lowercase or EIP-55. Responses are always checksummed.
- **Integers in `args`:** base-10 strings, whatever their width.
- **Bytes:** lowercase `0x` hex.
- **Tuples:** positional arrays.

Every rejection names the field and the value it would have accepted, e.g. `write it exactly as "deposit(uint256 assets, address receiver)"`.

The response is `200` with the executable address resource, the same one that lookup serves:

```json
{ "address": "0x461Dc8912aaB2840c401d987964bdf02D4E32935",
  "factory": "0x6D85B9706D8f076cB8A9fEA37d70Fcb8D22C2952",
  "intent": { "…": "the request, in canonical form" },
  "terms": "0x…" }
```

`terms` holds the calldata arguments of `PaymentFactory.paymentAddress` (selector `0x8809f6b6`) and
`PaymentFactory.execute` (selector `0xc5cdfc83`).

- **Deterministic:** the same body always returns the same address and the same `200`. Retries need
  no idempotency key.
- **Conflicting signatures:** a body with the same calldata but different function signatures is
  `409 address_conflict`.

### Credentials

The dashboard at execute.cash (Privy sign-in) holds an account's two credentials:

| Credential | Header | From |
|---|---|---|
| API key `exe_sk_…`, secret | `Authorization: Bearer exe_sk_…` | Your servers only. A request carrying it and an `Origin` header came from a browser and is refused with `403 api_key_in_browser`. |
| Client ID `exe_client_…`, publishable | `X-Client-Id: exe_client_…` | Your web pages. The browser's `Origin` must match one of the account's allowed origins (`https://app.example.com`, or `https://*.example.com` for subdomains). Otherwise the request fails with `403 origin_not_allowed`, or with `403 origin_required` when there is no `Origin`. |

Send exactly one credential. Each has its own rate limit.

Outside a browser, anyone can send any `Origin`. A client ID can only create addresses, which is
harmless, so treat it as public and rotate it if it is abused.

The public API answers CORS with `*`: nothing is sent with cookies, and the origin check happens on
the server. The dashboard, webhook and admin routes send no CORS headers.

### Lookup and status

`GET /v1/address/{address}` returns the create response for any address the API has created. It is
`404` for anything else.

- **Immutable.** An address's intent never changes, so responses carry `Cache-Control: public,
  max-age=31536000, immutable`.
- **Verifiable.** A wallet recomputes the address from the intent before trusting it.

`GET /v1/address/{address}/status` returns one state, each with its own fields:

```jsonc
{ "address": "0x…", "state": "awaiting_funds", "balance": "0",          "updatedAt": "…" }
{ "address": "0x…", "state": "funded",         "balance": "1000000000", "updatedAt": "…" }
{ "address": "0x…", "state": "failing",        "balance": "1000000000", "message": "settlement call 1 (to 0xbeef…) reverted: …", "revert": { /* decoded */ }, "updatedAt": "…" }
{ "address": "0x…", "state": "settled",        "transactionHash": "0x…", "blockNumber": 123, "updatedAt": "…" }
{ "address": "0x…", "state": "refunding",      "balance": "1000000000", "updatedAt": "…" }
{ "address": "0x…", "state": "refunded",       "transactionHash": "0x…", "blockNumber": 123, "amount": "1000000000", "updatedAt": "…" }
{ "address": "0x…", "state": "expired",        "balance": "0",          "updatedAt": "…" }
```

## Lifecycle

```
awaiting_funds ──balance reaches amount──▶ funded ──Settled──────────────▶ settled
      │                                      │  ▲
      │                                      ▼  │ retried with backoff
      │                                    failing
      │                                      │
      └──expiry: balance > 0──▶ refunding ◀──┘ expiry ──Recovered──▶ refunded
      └──expiry: nothing there──▶ expired ──a late payment──▶ refunding
```

1. **Watching.** Create registers a gum-indexer watch for the address. It lasts until
   `late_payment_window_secs` (a day) after expiry, so a late payment is still seen.
2. **Executing.** When the confirmed balance reaches `amount`, the address is `funded` and
   `PaymentFactory.execute` goes to gum-engine. The receipt decides the outcome: `Settled` from the
   address means `settled`; only `Recovered` (it executed after expiry) means `refunded`.
3. **Failing.** A reverting execute means `failing`, with the `Payment` constructor's revert decoded
   down to the call's own reason (e.g. `CallFailed(1, "vault is full")`). It is retried with
   backoff (`execute_retry_base_ms` up to `execute_retry_cap_ms`) until expiry.
4. **Expiry.** The reconciler runs every `expiry_interval_secs`. Once an address is past its expiry
   (plus `expiry_margin_secs`, so the chain's clock has passed it too):
   - a balance goes back to `recovery` (`refunding`, then `refunded`);
   - an empty address is `expired`;
   - a retry already in flight is left to finish, and landing after expiry, it refunds.
5. **Late payments.** Funds arriving after an address has executed stay there until someone calls
   `recover(token)` on it (permissionless). This is recorded as `address.late_payment`. Sweeping them
   automatically is future work.
6. **Unsupported outcomes.** `AlreadyDeployed` (someone else executed the address) and receipts
   without `Settled` or `Recovered` are `failing` without retries. An operator can retry with
   `POST /v1/admin/address/{address}/retry`.

Every transition is guarded by state (and by job id for execute outcomes), so redelivered or
reordered webhooks are harmless. The reconciler also polls gum-indexer and gum-engine for anything a
lost webhook left behind.

## Webhooks

An account can set a webhook URL. It then receives these events for every address it created:

- `address.detected`: seen at chain head, not counted yet
- `address.funded`
- `address.failing`
- `address.settled`
- `address.refunding`
- `address.refunded`
- `address.expired`

Delivery is at-least-once, in order per address. Failed deliveries are retried with backoff for 24 h.

```json
{ "id": "…", "type": "address.settled", "createdAt": "…", "sequence": 7,
  "address": "0x…", "chainId": 8453, "status": { "state": "settled", "…": "…" }, "data": { … } }
```

Each delivery carries these headers:

- `X-Execute-Event-Id`
- `X-Execute-Event-Type`
- `X-Execute-Delivery-Attempt`
- `X-Execute-Signature: t=<unix>,v1=<hex>`, where `v1 = HMAC-SHA256(webhookSecret, "<t>.<raw body>")`

Reject old timestamps. In production, the URL must be public `https`.

## Dashboard routes

These are for execute.cash only: a Privy session in `Authorization: Bearer`, proxied server-side.

```
GET    /v1/account                          id, apiKey {prefix, …} | null, clientId, allowedOrigins, webhookUrl, webhookSecret
POST   /v1/account/api-key                  201 { apiKey } shown once; 409 api_key_exists
POST   /v1/account/api-key/rotate           the old key stops working
POST   /v1/account/client-id/rotate         the old client ID stops working
PUT    /v1/account/allowed-origins          { "allowedOrigins": ["https://app.example.com"] }
PUT    /v1/account/webhook-url              { "webhookUrl": "https://…" }
DELETE /v1/account/webhook-url
POST   /v1/account/webhook-secret/rotate
GET    /v1/account/addresses?limit=&cursor= the account's addresses with their status, newest first
```

Operations:

```
POST /v1/webhooks/indexer    gum-indexer events (X-Gum-Signature, indexer.webhook_secret)
POST /v1/webhooks/engine     gum-engine events  (X-Gum-Signature, engine.webhook_secret)
GET  /healthz · /readyz · /metrics
POST /v1/admin/address/{address}/retry · GET /v1/admin/outbox · POST /v1/admin/outbox/{id}/requeue   (admin.token)
```

## Tokens

An address can be funded with the tokens configured per chain in `config/default.toml`:

| Chain | Tokens |
|---|---|
| Monad (143) | USDC, USDT (USDT0), AUSD |
| Arbitrum (42161) | USDC, USDT (USDT0) |
| Base (8453) | USDC |
| Arc (5042), off until enabled | USDC |

**Adding a token is a config change, in two places.** A vault's share token is the usual case, for
exit addresses where the user sends shares.

1. Add the token to gum-indexer's registry first, and deploy it. gum-indexer checks `decimals()` at
   boot, and only watches registry tokens.
2. Add it under `[[chains.<chain>.tokens]]` here, and deploy.

The reconciler compares this list with gum-indexer's `GET /v1/chains` every
`token_check_interval_secs`. It logs any token gum-indexer does not watch, and counts it in
`execute_tokens_unwatched`: payments of such a token would never be seen, so alert on it.

Before listing a new token, check that it behaves as `Payment` requires: its transfers must debit
exactly the amount sent. Rebasing or fee-on-transfer tokens break this; standard ERC-4626 vault
shares do not.

## Configuration

Configuration loads in three layers:

1. `config/default.toml`
2. `config/<EXECUTE_PROFILE>.toml`
3. the environment, as `EXECUTE_<SECTION>__<KEY>`

`DATABASE_URL` and `PORT` are read as-is. `.env.production.example` lists what production needs.

| Variable | |
|---|---|
| `EXECUTE_SERVER__CALLBACK_BASE_URL` | Where gum-indexer and gum-engine call back. This is the private network address: `http://execute-server.railway.internal:8080` |
| `EXECUTE_ADDRESSES__FACTORY_ADDRESS` | The `PaymentFactory` that `/v1` is pinned to |
| `EXECUTE_PRIVY__APP_ID`, `EXECUTE_PRIVY__VERIFICATION_KEY` | The execute.cash dashboard's Privy app |
| `EXECUTE_INDEXER__BASE_URL`, `EXECUTE_INDEXER__WEBHOOK_SECRET` | gum-indexer, and its `GUM_WEBHOOK__SECRET` |
| `EXECUTE_ENGINE__BASE_URL`, `EXECUTE_ENGINE__WEBHOOK_SECRET` | gum-engine, and its webhook signing secret |
| `EXECUTE_ADMIN__TOKEN` | Enables `/v1/admin` |
| `EXECUTE_CHAINS__<NAME>__ENABLED` | Offer a chain for new addresses |

gum-indexer delivers webhooks only to allowlisted private hosts. Add
`"execute-server.railway.internal"` to its `GUM_WEBHOOK__HOST_ALLOWLIST`.

## Local development and tests

```sh
docker compose up -d postgres            # or any Postgres; see .env.example
cp .env.example .env && set -a && . ./.env && set +a
cargo run                                # EXECUTE_PROFILE=local: Anvil chain, insecure webhook targets allowed

cargo test                                                        # unit tests
TEST_DATABASE_URL=postgres://execute:execute@127.0.0.1:54350/execute_server cargo test   # + end-to-end
```

The end-to-end suite starts the real server with a fresh database per test. It stubs gum-indexer,
gum-engine and an app's webhook with wiremock, and covers:

- creation, lookup and status;
- both credentials, allowed origins and CORS;
- the dashboard routes;
- webhook verification;
- every lifecycle path: settle, failing then refunded at expiry, a retry in flight at expiry, and
  expired then a late payment refunded.

The derivation is pinned to known answers from the real factory:

- the Base mainnet vector;
- the execute.cash landing page's Morpho deposit, `0x461Dc8912aaB2840c401d987964bdf02D4E32935`.

## Deploying

Railway builds the `Dockerfile`. Deploy it in the same Railway project and environment as
gum-indexer and gum-engine, because private networking doesn't cross projects:

1. Add Postgres. Migrations run at boot.
2. Set the variables above, and extend gum-indexer's host allowlist as described in Configuration.
3. Set the health check to `/readyz`, and give the service the public domain `api.execute.cash`.
