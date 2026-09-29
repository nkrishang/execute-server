//! The execution intent: what `POST /v1/address/create` takes, and what an executable address is
//! served with.
//!
//! An intent is exactly `PaymentFactory.paymentAddress`'s seven arguments, by their Solidity names
//! and in their order, except that each call is `{target, function, args}` rather than raw calldata:
//! the API does the ABI encoding, so every address it creates can be read back in words. Every field
//! is required, nothing else is accepted, and each value has one spelling (see `abi_json`).

pub mod abi_json;
pub mod function;

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::chain::Registry;
use crate::chain::payment::{self, Call, MAX_INIT_CODE_BYTES, PaymentTerms};
use crate::error::Issue;

/// The wire form of an intent, fields in the contract's order. This is the request body of
/// `POST /v1/address/create`, and the `intent` it and `GET /v1/address/{address}` serve back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentJson {
    pub token: String,
    pub amount: String,
    pub calls: Vec<CallJson>,
    pub expiration_timestamp: u64,
    pub recovery: String,
    pub salt: String,
    pub chain_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallJson {
    pub target: String,
    pub function: String,
    pub args: Vec<Value>,
}

/// A validated intent.
#[derive(Debug, Clone)]
pub struct Intent {
    pub token: Address,
    pub amount: U256,
    pub calls: Vec<IntentCall>,
    pub expiration_timestamp: u64,
    pub recovery: Address,
    pub salt: B256,
    pub chain_id: u64,
}

#[derive(Debug, Clone)]
pub struct IntentCall {
    pub target: Address,
    /// Canonical: `deposit(uint256 assets, address receiver)`.
    pub function: String,
    pub args: Vec<DynSolValue>,
    /// `selector ++ abi.encode(args)`, as the executable address will call it.
    pub data: Bytes,
}

impl Intent {
    pub fn terms(&self) -> PaymentTerms {
        PaymentTerms {
            token: self.token,
            amount: self.amount,
            calls: self.calls.iter().map(|c| Call { target: c.target, data: c.data.clone() }).collect(),
            expiration_timestamp: self.expiration_timestamp,
            recovery: self.recovery,
            salt: self.salt,
            chain_id: self.chain_id,
        }
    }

    /// The canonical wire form: addresses checksummed, every other value as accepted.
    pub fn to_json(&self) -> IntentJson {
        IntentJson {
            token: self.token.to_checksum(None),
            amount: self.amount.to_string(),
            calls: self
                .calls
                .iter()
                .map(|c| CallJson {
                    target: c.target.to_checksum(None),
                    function: c.function.clone(),
                    args: c.args.iter().map(abi_json::to_json).collect(),
                })
                .collect(),
            expiration_timestamp: self.expiration_timestamp,
            recovery: self.recovery.to_checksum(None),
            salt: format!("{:#x}", self.salt),
            chain_id: self.chain_id,
        }
    }
}

/// What an intent is checked against, besides its own shape.
pub struct Rules<'a> {
    pub registry: &'a Registry,
    pub factory: Address,
    /// Unix seconds.
    pub now: u64,
    pub min_expiry_lead_secs: u64,
    pub max_expiry_lead_secs: u64,
}

const FIELDS: [&str; 7] = ["token", "amount", "calls", "expirationTimestamp", "recovery", "salt", "chainId"];
const CALL_FIELDS: [&str; 3] = ["target", "function", "args"];

/// Validates a request body as an intent, reporting every problem at once.
pub fn parse(body: &Value, rules: &Rules<'_>) -> Result<Intent, Vec<Issue>> {
    let mut issues = Vec::new();
    let Value::Object(fields) = body else {
        return Err(vec![Issue::new(
            "",
            "expected a JSON object with token, amount, calls, expirationTimestamp, recovery, salt and chainId",
        )]);
    };
    unknown_fields(fields, &FIELDS, "", &mut issues);
    let field = |name: &str, issues: &mut Vec<Issue>| -> Option<Value> {
        let value = fields.get(name).cloned();
        if value.is_none() {
            issues.push(Issue::new(format!("/{name}"), "required"));
        }
        value
    };

    let token = field("token", &mut issues).and_then(|v| abi_json::address(&v, "/token", &mut issues));
    let amount = field("amount", &mut issues).and_then(|v| abi_json::uint(&v, 256, "/amount", &mut issues));
    if amount == Some(U256::ZERO) {
        issues.push(Issue::new("/amount", "must be greater than zero"));
    }
    let calls = field("calls", &mut issues).and_then(|v| parse_calls(&v, &mut issues));
    let expiration = field("expirationTimestamp", &mut issues).and_then(|v| expiration(&v, rules, &mut issues));
    let recovery = field("recovery", &mut issues).and_then(|v| abi_json::address(&v, "/recovery", &mut issues));
    let salt = field("salt", &mut issues)
        .and_then(|v| abi_json::hex_bytes(&v, Some(32), "/salt", &mut issues))
        .map(|b| B256::from_slice(&b));
    let chain = field("chainId", &mut issues).and_then(|v| chain_id(&v, rules, &mut issues));

    if let (Some(token), Some(chain)) = (token, chain) {
        let spec = rules.registry.chain(chain).expect("chain_id() checked it");
        if spec.token(token).is_none() {
            let supported: Vec<String> =
                spec.tokens.iter().map(|t| format!("{} ({})", t.symbol, t.address.to_checksum(None))).collect();
            issues.push(Issue::new(
                "/token",
                format!("Execute does not support this token on {}; supported: {}", spec.label(), supported.join(", ")),
            ));
        }
    }
    if let Some(token) = token
        && token.is_zero()
    {
        issues.push(Issue::new("/token", "must not be the zero address"));
    }
    if let Some(recovery) = recovery {
        let reason = if recovery.is_zero() {
            Some("must not be the zero address")
        } else if recovery == rules.factory || recovery == payment::payment_implementation(rules.factory) {
            Some("must not be a contract of Execute itself: funds sent there could never leave")
        } else if Some(recovery) == token {
            Some("must not be the token itself")
        } else {
            None
        };
        if let Some(reason) = reason {
            issues.push(Issue::new("/recovery", reason));
        }
    }

    let (
        Some(token),
        Some(amount),
        Some(calls),
        Some(expiration_timestamp),
        Some(recovery),
        Some(salt),
        Some(chain_id),
    ) = (token, amount, calls, expiration, recovery, salt, chain)
    else {
        return Err(issues);
    };
    if !issues.is_empty() {
        return Err(issues);
    }
    let intent = Intent { token, amount, calls, expiration_timestamp, recovery, salt, chain_id };
    let init_code = intent.terms().init_code_len();
    if init_code > MAX_INIT_CODE_BYTES {
        return Err(vec![Issue::new(
            "/calls",
            format!(
                "the calls make the init code {init_code} bytes; PaymentFactory accepts at most {MAX_INIT_CODE_BYTES} (EIP-3860)"
            ),
        )]);
    }
    Ok(intent)
}

fn parse_calls(value: &Value, issues: &mut Vec<Issue>) -> Option<Vec<IntentCall>> {
    let Value::Array(items) = value else {
        issues.push(Issue::new("/calls", "expected an array of calls, each {target, function, args}"));
        return None;
    };
    if items.is_empty() {
        issues.push(Issue::new("/calls", "expected at least one call: the calls are what spend `amount`"));
        return None;
    }
    let before = issues.len();
    let calls: Vec<Option<IntentCall>> =
        items.iter().enumerate().map(|(i, item)| parse_call(i, item, issues)).collect();
    if issues.len() > before {
        return None;
    }
    calls.into_iter().collect()
}

fn parse_call(index: usize, value: &Value, issues: &mut Vec<Issue>) -> Option<IntentCall> {
    let path = format!("/calls/{index}");
    let Value::Object(fields) = value else {
        issues.push(Issue::new(path, "expected an object {target, function, args}"));
        return None;
    };
    unknown_fields(fields, &CALL_FIELDS, &path, issues);
    let mut required = |name: &str| {
        let value = fields.get(name);
        if value.is_none() {
            issues.push(Issue::new(format!("{path}/{name}"), "required"));
        }
        value
    };
    let (target, function, args) = (required("target"), required("function"), required("args"));

    let target = target.and_then(|v| abi_json::address(v, &format!("{path}/target"), issues));
    if target.is_some_and(|t| t.is_zero()) {
        issues.push(Issue::new(format!("{path}/target"), "must not be the zero address"));
    }
    let function = function.and_then(|v| match v {
        Value::String(s) => match function::parse(s) {
            Ok(f) => Some((s.clone(), f)),
            Err(message) => {
                issues.push(Issue::new(format!("{path}/function"), message));
                None
            }
        },
        _ => {
            issues.push(Issue::new(
                format!("{path}/function"),
                "expected the function's signature as a string, e.g. \"deposit(uint256 assets, address receiver)\"",
            ));
            None
        }
    });
    let (Some(target), Some((signature, function)), Some(args)) = (target, function, args) else { return None };
    let types = match function::input_types(&function) {
        Ok(types) => types,
        Err(message) => {
            issues.push(Issue::new(format!("{path}/function"), message));
            return None;
        }
    };
    let Value::Array(values) = args else {
        issues.push(Issue::new(
            format!("{path}/args"),
            format!("expected an array of {} values, one per parameter of {signature}", types.len()),
        ));
        return None;
    };
    if values.len() != types.len() {
        issues.push(Issue::new(
            format!("{path}/args"),
            format!("expected {} values, one per parameter of {signature}; received {}", types.len(), values.len()),
        ));
        return None;
    }
    let before = issues.len();
    let args: Vec<Option<DynSolValue>> = types
        .iter()
        .zip(values)
        .enumerate()
        .map(|(k, (ty, v))| abi_json::from_json(ty, v, &format!("{path}/args/{k}"), issues))
        .collect();
    if issues.len() > before {
        return None;
    }
    let args: Vec<DynSolValue> = args.into_iter().collect::<Option<_>>()?;
    match function.abi_encode_input(&args) {
        Ok(data) => Some(IntentCall { target, function: signature, args, data: data.into() }),
        Err(e) => {
            issues.push(Issue::new(format!("{path}/args"), format!("could not be encoded: {e}")));
            None
        }
    }
}

fn expiration(value: &Value, rules: &Rules<'_>, issues: &mut Vec<Issue>) -> Option<u64> {
    let path = "/expirationTimestamp";
    let example = rules.now + rules.max_expiry_lead_secs;
    let Some(timestamp) = value.as_u64() else {
        let received = match value {
            Value::String(s) => format!("the string \"{s}\""),
            other => other.to_string(),
        };
        issues.push(Issue::new(
            path,
            format!("expected unix seconds as a JSON integer, such as {example}; received {received}"),
        ));
        return None;
    };
    let (min, max) = (rules.now + rules.min_expiry_lead_secs, rules.now + rules.max_expiry_lead_secs);
    if timestamp < min {
        let message = if timestamp <= rules.now {
            format!(
                "is in the past; it must be {}–{} seconds from now",
                rules.min_expiry_lead_secs, rules.max_expiry_lead_secs
            )
        } else {
            format!(
                "must be at least {} seconds from now; it is {} seconds away",
                rules.min_expiry_lead_secs,
                timestamp - rules.now
            )
        };
        issues.push(Issue::new(path, message));
        return None;
    }
    if timestamp > max {
        let seconds = timestamp / 1000;
        let message = if (min..=max).contains(&seconds) {
            format!("looks like milliseconds; in seconds that is {seconds}")
        } else {
            format!(
                "must be at most {} seconds from now; it is {} seconds away",
                rules.max_expiry_lead_secs,
                timestamp - rules.now
            )
        };
        issues.push(Issue::new(path, message));
        return None;
    }
    Some(timestamp)
}

fn chain_id(value: &Value, rules: &Rules<'_>, issues: &mut Vec<Issue>) -> Option<u64> {
    let path = "/chainId";
    let live: Vec<String> = rules.registry.chains().map(|c| c.label()).collect();
    let Some(chain_id) = value.as_u64() else {
        let received = match value {
            Value::String(s) => format!("the string \"{s}\""),
            other => other.to_string(),
        };
        issues.push(Issue::new(path, format!("expected a JSON integer such as 8453; received {received}")));
        return None;
    };
    match rules.registry.chain(chain_id) {
        Some(spec) if spec.enabled => Some(chain_id),
        Some(spec) => {
            issues.push(Issue::new(
                path,
                format!("Execute is not live on {} yet; live: {}", spec.label(), live.join(", ")),
            ));
            None
        }
        None => {
            issues
                .push(Issue::new(path, format!("Execute is not live on chain {chain_id}; live: {}", live.join(", "))));
            None
        }
    }
}

/// Flags every key that is not one of `known`, suggesting the one it probably meant.
fn unknown_fields(fields: &Map<String, Value>, known: &[&str], path: &str, issues: &mut Vec<Issue>) {
    for key in fields.keys().filter(|k| !known.contains(&k.as_str())) {
        issues.push(Issue::new(format!("{path}/{key}"), format!("unknown field{}", suggestion(key, known))));
    }
}

fn suggestion(key: &str, known: &[&str]) -> String {
    let normal = |s: &str| s.to_ascii_lowercase().replace(['_', '-'], "");
    if let Some(k) = known.iter().find(|k| normal(k) == normal(key)) {
        return format!("; did you mean \"{k}\"?");
    }
    let hint = match normal(key).as_str() {
        "data" | "calldata" => {
            "; raw calldata is not accepted: send \"function\" and \"args\" and the API encodes them"
        }
        "to" | "contract" | "address" if known.contains(&"target") => "; did you mean \"target\"?",
        "abi" | "signature" | "method" | "functionname" | "fn" => "; did you mean \"function\"?",
        "params" | "arguments" | "inputs" | "values" => "; did you mean \"args\"?",
        "value" => "; calls carry no native value",
        "expiration" | "expiry" | "expiresat" | "deadline" | "expirationtime" => {
            "; did you mean \"expirationTimestamp\"?"
        }
        "chain" | "network" => "; did you mean \"chainId\"?",
        "receiver" | "recipient" => {
            "; there is no receiver: a plain payment is one call, transfer(address to, uint256 amount), and \"recovery\" receives what cannot be spent"
        }
        "refundaddress" | "refundto" | "refund" | "fallback" => "; did you mean \"recovery\"?",
        "nonce" => "; did you mean \"salt\"?",
        "factory" => "; the factory is fixed by the API version, so it is not part of the request",
        _ => "",
    };
    hint.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainConfig, TokenConfig};
    use alloy_primitives::address;
    use serde_json::json;
    use std::collections::BTreeMap;

    const NOW: u64 = 1_799_999_800;
    const FACTORY: Address = address!("6D85B9706D8f076cB8A9fEA37d70Fcb8D22C2952");

    fn registry() -> Registry {
        let usdc = TokenConfig {
            symbol: "USDC".into(),
            address: address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            decimals: 6,
        };
        Registry::from_config(&BTreeMap::from([
            ("base".to_owned(), ChainConfig { chain_id: 8453, enabled: true, tokens: vec![usdc.clone()] }),
            ("arc".to_owned(), ChainConfig { chain_id: 5042, enabled: false, tokens: vec![usdc] }),
        ]))
    }

    /// The landing page's Morpho deposit: 1,000 USDC into Steakhouse Prime USDC on Base.
    fn morpho() -> Value {
        json!({
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
            "expirationTimestamp": 1800000000u64,
            "recovery": "0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086",
            "salt": "0x4b7ef6dd50ef7570851a0abfbf121fa35edfcdd5f83d07e6bc275547447ec004",
            "chainId": 8453
        })
    }

    fn check(body: &Value) -> Result<Intent, Vec<Issue>> {
        let registry = registry();
        parse(
            body,
            &Rules {
                registry: &registry,
                factory: FACTORY,
                now: NOW,
                min_expiry_lead_secs: 60,
                max_expiry_lead_secs: 300,
            },
        )
    }

    fn issues(body: Value) -> Vec<(String, String)> {
        check(&body).unwrap_err().into_iter().map(|i| (i.path, i.message)).collect()
    }

    #[test]
    fn derives_the_landing_pages_morpho_address_and_echoes_the_request() {
        let intent = check(&morpho()).unwrap();
        // The address the landing page shows and PaymentFactory.paymentAddress returns on Base.
        assert_eq!(intent.terms().payment_address(FACTORY), address!("461Dc8912aaB2840c401d987964bdf02D4E32935"));
        assert_eq!(serde_json::to_value(intent.to_json()).unwrap(), morpho());
        // Served in the contract's order: token, amount, calls, expirationTimestamp, recovery, salt, chainId.
        let text = serde_json::to_string(&intent.to_json()).unwrap();
        let at = |key: &str| text.find(&format!("\"{key}\":")).unwrap();
        let order = ["token", "amount", "calls", "expirationTimestamp", "recovery", "salt", "chainId"].map(at);
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
        assert!(text.contains(r#"{"target":"0xbeef0e0834849aCC03f0089F01f4F1Eeb06873C9","function":"deposit(uint256 assets, address receiver)","args":["#));
    }

    #[test]
    fn lowercase_addresses_are_accepted_and_echoed_checksummed() {
        let mut body = morpho();
        body["recovery"] = json!("0xc80d2a01247ad9e11d1ab45b5ace404b416af086");
        body["calls"][1]["args"][1] = json!("0xc80d2a01247ad9e11d1ab45b5ace404b416af086");
        assert_eq!(serde_json::to_value(check(&body).unwrap().to_json()).unwrap(), morpho());
    }

    #[test]
    fn reports_every_problem_at_once_with_what_to_send() {
        let mut body = morpho();
        body["amount"] = json!(1000000000);
        body["chainId"] = json!("8453");
        body["expirationTimestamp"] = json!(1_800_000_000_000u64);
        body["calls"][1]["function"] =
            json!("function deposit(uint256 assets, address receiver) returns (uint256 shares)");
        let found = issues(body);
        let paths: Vec<&str> = found.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["/amount", "/calls/1/function", "/expirationTimestamp", "/chainId"]);
        assert!(found[0].1.contains("\"1000000000\", not a JSON number"));
        assert!(found[1].1.contains("write it exactly as \"deposit(uint256 assets, address receiver)\""));
        assert!(found[2].1.contains("looks like milliseconds; in seconds that is 1800000000"));
        assert!(found[3].1.contains("expected a JSON integer such as 8453"));
    }

    #[test]
    fn unknown_and_missing_fields_are_named() {
        let mut body = morpho();
        let fields = body.as_object_mut().unwrap();
        let expiry = fields.remove("expirationTimestamp").unwrap();
        fields.insert("expiration_timestamp".into(), expiry);
        fields.insert("receiver".into(), json!("0x0000000000000000000000000000000000000001"));
        body["calls"][0].as_object_mut().unwrap().insert("data".into(), json!("0x"));
        let found = issues(body);
        assert!(found.contains(&(
            "/expiration_timestamp".into(),
            "unknown field; did you mean \"expirationTimestamp\"?".into()
        )));
        assert!(found.iter().any(|(p, m)| p == "/receiver" && m.contains("there is no receiver")));
        assert!(found.iter().any(|(p, m)| p == "/calls/0/data" && m.contains("raw calldata is not accepted")));
        assert!(found.contains(&("/expirationTimestamp".into(), "required".into())));
    }

    #[test]
    fn chains_tokens_and_bounds() {
        let with = |f: &dyn Fn(&mut Value)| {
            let mut body = morpho();
            f(&mut body);
            issues(body)
        };
        assert!(with(&|b| b["chainId"] = json!(1))[0].1.contains("not live on chain 1; live: Base (8453)"));
        assert!(with(&|b| b["chainId"] = json!(5042))[0].1.contains("not live on Arc (5042) yet"));
        let token = with(&|b| b["token"] = json!("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"));
        assert_eq!(token[0].0, "/token");
        assert!(token[0].1.contains("supported: USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)"));
        assert!(with(&|b| b["expirationTimestamp"] = json!(NOW + 30))[0].1.contains("at least 60 seconds"));
        assert!(with(&|b| b["expirationTimestamp"] = json!(NOW + 301))[0].1.contains("at most 300 seconds"));
        assert!(with(&|b| b["expirationTimestamp"] = json!(NOW - 1))[0].1.contains("in the past"));
        assert!(with(&|b| b["amount"] = json!("0"))[0].1.contains("greater than zero"));
        assert!(with(&|b| b["calls"] = json!([]))[0].1.contains("at least one call"));
        assert!(
            with(&|b| b["recovery"] = json!("0x6D85B9706D8f076cB8A9fEA37d70Fcb8D22C2952"))[0]
                .1
                .contains("contract of Execute")
        );
        assert!(with(&|b| b["salt"] = json!("0x01"))[0].1.contains("exactly 32 bytes"));
        assert!(with(&|b| b["calls"][1]["args"] = json!(["1000000000"]))[0].1.contains("expected 2 values"));
    }

    #[test]
    fn oversized_calls_are_refused_like_the_factory_would() {
        let mut body = morpho();
        body["calls"][0] = json!({
            "target": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "function": "notify(bytes payload)",
            "args": [format!("0x{}", "00".repeat(48_000))]
        });
        let found = issues(body);
        assert_eq!(found[0].0, "/calls");
        assert!(found[0].1.contains("at most 49152"));
    }
}
