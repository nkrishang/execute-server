//! One JSON form per ABI type, in both directions.
//!
//! | ABI type            | JSON                                                         |
//! |---------------------|--------------------------------------------------------------|
//! | `address`           | string, all lowercase or EIP-55 checksummed                  |
//! | `uint<N>`, `int<N>` | base-10 string: no sign (but `-`), decimal point or leading zeros |
//! | `bool`              | `true` / `false`                                             |
//! | `bytes<N>`, `bytes` | lowercase `0x` hex, exactly N bytes for `bytes<N>`           |
//! | `string`            | string                                                       |
//! | arrays and tuples   | JSON arrays, tuples positional                               |
//!
//! Every rejection says what would have been accepted. Values are read back in canonical form:
//! addresses checksummed, everything else exactly as accepted.

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, B256, I256, U256};
use serde_json::Value;

use crate::error::Issue;

/// Reads `value` as `ty`, recording a problem at `path` (a JSON Pointer) for anything that is not
/// its canonical form. `None` when anything was recorded.
pub fn from_json(ty: &DynSolType, value: &Value, path: &str, issues: &mut Vec<Issue>) -> Option<DynSolValue> {
    let before = issues.len();
    let out = read(ty, value, path, issues);
    if issues.len() > before { None } else { out }
}

fn read(ty: &DynSolType, value: &Value, path: &str, issues: &mut Vec<Issue>) -> Option<DynSolValue> {
    match ty {
        DynSolType::Address => address(value, path, issues).map(DynSolValue::Address),
        DynSolType::Bool => match value {
            Value::Bool(b) => Some(DynSolValue::Bool(*b)),
            _ => fail(issues, path, format!("expected true or false for bool; received {}", describe(value))),
        },
        DynSolType::Uint(bits) => uint(value, *bits, path, issues).map(|v| DynSolValue::Uint(v, *bits)),
        DynSolType::Int(bits) => int(value, *bits, path, issues).map(|v| DynSolValue::Int(v, *bits)),
        DynSolType::FixedBytes(size) => {
            let bytes = hex_bytes(value, Some(*size), path, issues)?;
            let mut word = B256::ZERO;
            word[..*size].copy_from_slice(&bytes);
            Some(DynSolValue::FixedBytes(word, *size))
        }
        DynSolType::Bytes => hex_bytes(value, None, path, issues).map(DynSolValue::Bytes),
        DynSolType::String => match value {
            Value::String(s) => Some(DynSolValue::String(s.clone())),
            _ => fail(issues, path, format!("expected a JSON string for string; received {}", describe(value))),
        },
        DynSolType::Array(inner) => {
            let Value::Array(items) = value else {
                return fail(
                    issues,
                    path,
                    format!("expected a JSON array for {}; received {}", ty.sol_type_name(), describe(value)),
                );
            };
            let values: Vec<_> =
                items.iter().enumerate().map(|(i, v)| read(inner, v, &format!("{path}/{i}"), issues)).collect();
            values.into_iter().collect::<Option<Vec<_>>>().map(DynSolValue::Array)
        }
        DynSolType::FixedArray(inner, len) => {
            let Value::Array(items) = value else {
                return fail(
                    issues,
                    path,
                    format!("expected a JSON array of {len} for {}; received {}", ty.sol_type_name(), describe(value)),
                );
            };
            if items.len() != *len {
                return fail(
                    issues,
                    path,
                    format!("expected exactly {len} elements for {}; received {}", ty.sol_type_name(), items.len()),
                );
            }
            let values: Vec<_> =
                items.iter().enumerate().map(|(i, v)| read(inner, v, &format!("{path}/{i}"), issues)).collect();
            values.into_iter().collect::<Option<Vec<_>>>().map(DynSolValue::FixedArray)
        }
        DynSolType::Tuple(types) => {
            let Value::Array(items) = value else {
                return fail(
                    issues,
                    path,
                    format!(
                        "expected a JSON array of the tuple's {} components, in order; received {}",
                        types.len(),
                        describe(value)
                    ),
                );
            };
            if items.len() != types.len() {
                return fail(
                    issues,
                    path,
                    format!("expected the tuple's {} components; received {}", types.len(), items.len()),
                );
            }
            let values: Vec<_> = types
                .iter()
                .zip(items)
                .enumerate()
                .map(|(i, (t, v))| read(t, v, &format!("{path}/{i}"), issues))
                .collect();
            values.into_iter().collect::<Option<Vec<_>>>().map(DynSolValue::Tuple)
        }
        _ => fail(issues, path, format!("{} arguments are not supported", ty.sol_type_name())),
    }
}

fn fail<T>(issues: &mut Vec<Issue>, path: &str, message: String) -> Option<T> {
    issues.push(Issue::new(path, message));
    None
}

fn describe(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => format!("the boolean {b}"),
        Value::Number(n) => format!("the JSON number {n}"),
        Value::String(s) if s.chars().count() > 80 => format!("a {}-character string", s.chars().count()),
        Value::String(s) => format!("the string \"{s}\""),
        Value::Array(_) => "an array".into(),
        Value::Object(_) => "an object".into(),
    }
}

/// An address: `0x` and 40 hex digits, all lowercase or EIP-55 checksummed.
pub fn address(value: &Value, path: &str, issues: &mut Vec<Issue>) -> Option<Address> {
    let Value::String(s) = value else {
        return fail(
            issues,
            path,
            format!(
                "expected an address string such as \"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913\"; received {}",
                describe(value)
            ),
        );
    };
    let valid = s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if !valid {
        return fail(issues, path, format!("expected 0x and 40 hex digits; received {}", describe(value)));
    }
    let address: Address = s.parse().expect("checked above");
    let checksummed = address.to_checksum(None);
    if *s != s.to_ascii_lowercase() && *s != checksummed {
        return fail(issues, path, format!("bad EIP-55 checksum; did you mean \"{checksummed}\"?"));
    }
    Some(address)
}

/// An unsigned integer as a base-10 string.
pub fn uint(value: &Value, bits: usize, path: &str, issues: &mut Vec<Issue>) -> Option<U256> {
    let s = match value {
        Value::String(s) => s,
        Value::Number(n) => {
            return fail(issues, path, format!("expected a base-10 string such as \"{n}\", not a JSON number"));
        }
        other => return fail(issues, path, format!("expected a base-10 integer string; received {}", describe(other))),
    };
    let canonical = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if !canonical {
        let hint = match s.strip_prefix("0x").and_then(|h| U256::from_str_radix(h, 16).ok()) {
            Some(v) => format!("; you sent hex, which is \"{v}\" in base 10"),
            None => String::new(),
        };
        return fail(
            issues,
            path,
            format!("expected a base-10 integer string with no sign, decimal point or leading zeros{hint}"),
        );
    }
    let Ok(v) = U256::from_str_radix(s, 10) else {
        return fail(issues, path, format!("does not fit uint{bits}"));
    };
    if bits < 256 && v >> bits != U256::ZERO {
        return fail(issues, path, format!("does not fit uint{bits}"));
    }
    Some(v)
}

/// A signed integer as a base-10 string.
fn int(value: &Value, bits: usize, path: &str, issues: &mut Vec<Issue>) -> Option<I256> {
    let s = match value {
        Value::String(s) => s,
        Value::Number(n) => {
            return fail(issues, path, format!("expected a base-10 string such as \"{n}\", not a JSON number"));
        }
        other => return fail(issues, path, format!("expected a base-10 integer string; received {}", describe(other))),
    };
    let digits = s.strip_prefix('-').unwrap_or(s);
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && s != "-0";
    if !canonical {
        return fail(
            issues,
            path,
            "expected a base-10 integer string such as \"-5\", with no \"+\", decimal point or leading zeros".into(),
        );
    }
    let Ok(v) = s.parse::<I256>() else { return fail(issues, path, format!("does not fit int{bits}")) };
    if bits < 256 {
        let limit = I256::ONE << (bits - 1);
        if v >= limit || v < -limit {
            return fail(issues, path, format!("does not fit int{bits}"));
        }
    }
    Some(v)
}

/// Lowercase `0x` hex; exactly `size` bytes when given.
pub fn hex_bytes(value: &Value, size: Option<usize>, path: &str, issues: &mut Vec<Issue>) -> Option<Vec<u8>> {
    let what = match size {
        Some(n) => format!("exactly {n} bytes as lowercase 0x hex"),
        None => "lowercase 0x hex of even length (\"0x\" when empty)".into(),
    };
    let Value::String(s) = value else {
        return fail(issues, path, format!("expected {what}; received {}", describe(value)));
    };
    let Some(digits) = s.strip_prefix("0x") else {
        return fail(issues, path, format!("expected {what}; received {}", describe(value)));
    };
    if digits.len() % 2 != 0 || !digits.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        let hint = if digits.bytes().any(|b| b.is_ascii_uppercase()) { " (use lowercase)" } else { "" };
        return fail(issues, path, format!("expected {what}{hint}"));
    }
    let bytes = hex::decode(digits).expect("checked above");
    if let Some(n) = size
        && bytes.len() != n
    {
        return fail(issues, path, format!("expected {what}; received {} bytes", bytes.len()));
    }
    Some(bytes)
}

/// The canonical JSON of a value: what the API echoes and serves.
pub fn to_json(value: &DynSolValue) -> Value {
    match value {
        DynSolValue::Address(a) => Value::String(a.to_checksum(None)),
        DynSolValue::Bool(b) => Value::Bool(*b),
        DynSolValue::Uint(v, _) => Value::String(v.to_string()),
        DynSolValue::Int(v, _) => Value::String(v.to_string()),
        DynSolValue::FixedBytes(word, size) => Value::String(format!("0x{}", hex::encode(&word[..*size]))),
        DynSolValue::Bytes(b) => Value::String(format!("0x{}", hex::encode(b))),
        DynSolValue::String(s) => Value::String(s.clone()),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            Value::Array(items.iter().map(to_json).collect())
        }
        other => Value::String(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read_one(ty: &str, value: Value) -> Result<Value, String> {
        let ty = DynSolType::parse(ty).unwrap();
        let mut issues = Vec::new();
        match from_json(&ty, &value, "/x", &mut issues) {
            Some(v) => Ok(to_json(&v)),
            None => Err(issues.into_iter().map(|i| i.message).collect::<Vec<_>>().join("; ")),
        }
    }

    #[test]
    fn canonical_values_round_trip() {
        let cases = [
            ("address", json!("0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086")),
            ("uint256", json!("1000000000")),
            ("uint8", json!("255")),
            ("uint16", json!("0")),
            ("int128", json!("-5")),
            ("bool", json!(true)),
            ("bytes32", json!(format!("0x{}", "ab".repeat(32)))),
            ("bytes4", json!("0x095ea7b3")),
            ("bytes", json!("0x")),
            ("string", json!("hello")),
            ("uint256[]", json!(["1", "2"])),
            ("uint256[2]", json!(["1", "2"])),
            ("(address,uint256)[]", json!([["0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086", "5"]])),
        ];
        for (ty, value) in cases {
            assert_eq!(read_one(ty, value.clone()).unwrap_or_else(|e| panic!("{ty}: {e}")), value, "{ty}");
        }
    }

    #[test]
    fn lowercase_addresses_are_accepted_and_served_checksummed() {
        assert_eq!(
            read_one("address", json!("0xc80d2a01247ad9e11d1ab45b5ace404b416af086")).unwrap(),
            json!("0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086")
        );
    }

    #[test]
    fn every_other_spelling_is_rejected_with_what_to_send() {
        let err = |ty: &str, v: Value| read_one(ty, v).unwrap_err();
        assert!(err("uint256", json!(1000000000)).contains("\"1000000000\", not a JSON number"));
        assert!(err("uint256", json!("0x3b9aca00")).contains("which is \"1000000000\" in base 10"));
        for bad in ["1000.0", "1e9", "+1", "01", "", " 1", "-1"] {
            assert!(err("uint256", json!(bad)).contains("base-10"), "{bad}");
        }
        assert!(err("uint8", json!("256")).contains("does not fit uint8"));
        assert!(err("int8", json!("128")).contains("does not fit int8"));
        assert!(read_one("int8", json!("-128")).is_ok());
        assert!(err("int8", json!("-0")).contains("base-10"));
        assert!(
            err("address", json!("0xC80d2a01247aD9e11D1Ab45B5AcE404B416aF086"))
                .contains("did you mean \"0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086\"")
        );
        assert!(err("address", json!("vitalik.eth")).contains("40 hex digits"));
        assert!(err("bool", json!("true")).contains("true or false"));
        assert!(err("bytes32", json!(format!("0x{}", "AB".repeat(32)))).contains("use lowercase"));
        assert!(err("bytes4", json!("0x095ea7")).contains("received 3 bytes"));
        assert!(err("bytes", json!("0x0")).contains("even length"));
        assert!(err("uint256[2]", json!(["1"])).contains("exactly 2 elements"));
        assert!(err("(address,uint256)", json!({"a": 1})).contains("tuple's 2 components"));
    }

    #[test]
    fn nested_problems_point_at_the_element() {
        let ty = DynSolType::parse("(address,uint256)[]").unwrap();
        let mut issues = Vec::new();
        assert!(
            from_json(&ty, &json!([["0xc80d2a01247aD9e11D1Ab45B5AcE404B416aF086", 5]]), "/calls/0/args/1", &mut issues)
                .is_none()
        );
        assert_eq!(issues[0].path, "/calls/0/args/1/0/1");
    }
}
