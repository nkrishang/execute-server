-- execute-server schema. Addresses and hashes are 0x-prefixed lowercase hex text. Token amounts are
-- base-unit integers (NUMERIC(78,0) fits uint256).

-- One account per Privy user. It holds two credentials: a secret API key for servers (`api_keys`) and a
-- publishable client ID for browsers, accepted only from `allowed_origins`.
CREATE TABLE accounts (
    id              TEXT PRIMARY KEY,                    -- Privy DID (did:privy:…)
    client_id       TEXT NOT NULL UNIQUE,                -- exe_client_…; public by design
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',        -- e.g. {https://app.example.com, https://*.example.com}
    webhook_url     TEXT,
    webhook_secret  TEXT NOT NULL,                       -- HMAC secret for the webhooks we send
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One secret key per account; rotation rewrites the row in place.
CREATE TABLE api_keys (
    account_id   TEXT PRIMARY KEY REFERENCES accounts (id),
    key_hash     BYTEA NOT NULL UNIQUE,                  -- sha256(secret)
    key_prefix   TEXT NOT NULL,                          -- display only, e.g. exe_sk_1a2b3c4d
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE TYPE address_state AS ENUM (
    'awaiting_funds', -- not yet holding `amount`, before expiry
    'funded',         -- holds `amount`; PaymentFactory.execute is in flight
    'failing',        -- execute reverts (e.g. a call fails); retried until expiry, then refunded
    'settled',        -- executed: every call ran and together they spent exactly `amount`
    'refunding',      -- past expiry with a balance; executing to return it to `recovery`
    'refunded',       -- executed after expiry: the balance went to `recovery`
    'expired'         -- past expiry with nothing to return
);

-- The registry: every executable address the API has created, keyed by the address itself. An
-- address commits to its terms, so a row never changes what it describes; only its state moves.
CREATE TABLE addresses (
    address             TEXT PRIMARY KEY,
    factory             TEXT NOT NULL,
    chain_id            BIGINT NOT NULL,
    token               TEXT NOT NULL,
    amount              NUMERIC(78, 0) NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,            -- expirationTimestamp
    intent              JSON NOT NULL,                   -- canonical intent; JSON (not JSONB) keeps its text and key order
    terms               TEXT NOT NULL,                   -- 0x hex: the calldata arguments of PaymentFactory.execute
    state               address_state NOT NULL DEFAULT 'awaiting_funds',
    balance             NUMERIC(78, 0) NOT NULL DEFAULT 0, -- confirmed balance, as gum-indexer counts it
    watch_id            UUID,
    watch_registered_at TIMESTAMPTZ,
    engine_job_id       UUID,                            -- the execute job in flight, if any
    engine_submitted_at TIMESTAMPTZ,
    execute_attempts    INT NOT NULL DEFAULT 0,
    tx_hash             TEXT,
    block_number        BIGINT,
    refunded_amount     NUMERIC(78, 0),
    failure_code        TEXT,                            -- failing: why the last attempt failed
    failure_message     TEXT,
    revert_data         TEXT,                            -- failing: 0x hex of execute's revert data, when known
    event_seq           BIGINT NOT NULL DEFAULT 0,
    detected_at         TIMESTAMPTZ,
    funded_at           TIMESTAMPTZ,
    settled_at          TIMESTAMPTZ,
    refunded_at         TIMESTAMPTZ,
    expired_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX addresses_watch_idx ON addresses (watch_id) WHERE watch_id IS NOT NULL;
CREATE INDEX addresses_expiry_idx ON addresses (expires_at) WHERE state IN ('awaiting_funds', 'failing');
CREATE INDEX addresses_open_idx ON addresses (updated_at) WHERE state = 'awaiting_funds';
CREATE INDEX addresses_in_flight_idx ON addresses (updated_at) WHERE engine_job_id IS NOT NULL;

-- Who created an address. The same intent created twice is the same address, and every account
-- that created it gets its webhooks.
CREATE TABLE address_accounts (
    address    TEXT NOT NULL REFERENCES addresses (address),
    account_id TEXT NOT NULL REFERENCES accounts (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (address, account_id)
);
CREATE INDEX address_accounts_account_idx ON address_accounts (account_id, created_at DESC, address DESC);

-- Timeline of everything that happened to an address; mirrored to app webhooks.
CREATE TABLE address_events (
    id         UUID PRIMARY KEY,
    address    TEXT NOT NULL REFERENCES addresses (address),
    sequence   BIGINT NOT NULL,
    type       TEXT NOT NULL,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (address, sequence)
);

-- Every gum-engine job submitted for an address. Only the one in `addresses.engine_job_id` is live;
-- events for superseded jobs are acknowledged and ignored.
CREATE TABLE engine_jobs (
    job_id       UUID PRIMARY KEY,
    address      TEXT NOT NULL REFERENCES addresses (address),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX engine_jobs_address_idx ON engine_jobs (address);

-- Inbound webhook dedupe (gum-indexer and gum-engine both deliver at-least-once).
CREATE TABLE inbound_events (
    source      TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, event_id)
);
CREATE INDEX inbound_events_received_idx ON inbound_events (received_at);

-- Transactional outbox: side effects are committed with the state change that caused them and run
-- by background workers with retries. Rows are deleted on success.
CREATE TABLE outbox (
    id              UUID PRIMARY KEY,                    -- uuid v7: creation order
    kind            TEXT NOT NULL,                       -- register_watch | submit_execute | notify_app
    address         TEXT NOT NULL REFERENCES addresses (address),
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempts        INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until    TIMESTAMPTZ,
    last_error      TEXT,
    dead_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX outbox_due_idx ON outbox (next_attempt_at) WHERE dead_at IS NULL;
CREATE INDEX outbox_address_idx ON outbox (address, kind, id);
