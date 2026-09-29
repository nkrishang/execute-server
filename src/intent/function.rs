//! A call's `function`: its Solidity signature with parameter names, in one canonical form.
//!
//! ```text
//! function   = name "(" [ param *( ", " param ) ] ")"
//! param      = type " " name
//! type       = ( elementary / "(" param *( ", " param ) ")" ) *( "[" [ digits ] "]" )
//! ```
//!
//! No `function` keyword, visibility, mutability, `returns (…)` or data location; canonical types
//! (`uint256`, never `uint`); every parameter named, names unique within their list. It is the inputs
//! half of what abitype's `formatAbiItem` and ethers' `format("full")` print, so viem reads it as
//! `parseAbiItem("function " + fn)`, and ethers and alloy read it as is. A name abitype refuses (a
//! Solidity keyword) is refused here too, so every accepted signature parses in every library.

use alloy_dyn_abi::{DynSolType, Specifier};
use alloy_json_abi::{Function, Param, StateMutability};

/// Parses a canonical signature, or says exactly what to send instead.
pub fn parse(signature: &str) -> Result<Function, String> {
    let function = parse_loose(signature).map_err(|e| format!("not a Solidity function signature: {e}"))?;
    check_names(&function.inputs, true)?;
    let canonical = canonical(&function)?;
    if canonical != signature {
        return Err(format!(
            "write it exactly as \"{canonical}\" (no \"function\" keyword, modifiers or returns; one space after each comma)"
        ));
    }
    Ok(function)
}

/// Reads any reasonable spelling of a function signature (with or without the `function` keyword,
/// modifiers, `returns (…)`, data locations, `tuple(…)`, loose whitespace), so a non-canonical one can
/// be answered with its canonical form. alloy's own parser cannot name tuple components, which
/// abitype and ethers both write, hence this one.
fn parse_loose(signature: &str) -> Result<Function, String> {
    let mut c = Cursor { s: signature.as_bytes(), i: 0 };
    c.ws();
    if c.keyword("function") {
        c.ws();
    }
    let name = c.ident().ok_or("expected the function's name")?.to_owned();
    c.ws();
    let inputs = params_list(&mut c)?;
    loop {
        c.ws();
        if c.at_end() {
            break;
        }
        match c.ident() {
            Some("returns") => {
                c.ws();
                params_list(&mut c)?;
            }
            Some("external" | "public" | "view" | "pure" | "payable" | "nonpayable" | "virtual" | "override") => {}
            Some(word) => return Err(format!("unexpected \"{word}\" after the parameters")),
            None => return Err("unexpected text after the parameters".into()),
        }
    }
    Ok(Function { name, inputs, outputs: vec![], state_mutability: StateMutability::NonPayable })
}

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(u8::is_ascii_whitespace) {
            self.i += 1;
        }
    }

    fn at_end(&self) -> bool {
        self.i >= self.s.len()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.i += 1;
            return true;
        }
        false
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.eat(b) { Ok(()) } else { Err(format!("expected \"{}\" at position {}", b as char, self.i)) }
    }

    /// `[A-Za-z_$][A-Za-z0-9_$]*`
    fn ident(&mut self) -> Option<&'a str> {
        let start = self.i;
        let first = self.peek()?;
        if !(first.is_ascii_alphabetic() || first == b'_' || first == b'$') {
            return None;
        }
        while self.peek().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$') {
            self.i += 1;
        }
        std::str::from_utf8(&self.s[start..self.i]).ok()
    }

    /// Consumes `word` when it is the next identifier.
    fn keyword(&mut self, word: &str) -> bool {
        let save = self.i;
        if self.ident() == Some(word) {
            return true;
        }
        self.i = save;
        false
    }
}

fn params_list(c: &mut Cursor<'_>) -> Result<Vec<Param>, String> {
    c.expect(b'(')?;
    c.ws();
    let mut out = Vec::new();
    if c.eat(b')') {
        return Ok(out);
    }
    loop {
        out.push(param(c)?);
        c.ws();
        if c.eat(b',') {
            c.ws();
            continue;
        }
        c.expect(b')')?;
        return Ok(out);
    }
}

fn param(c: &mut Cursor<'_>) -> Result<Param, String> {
    c.ws();
    let (ty, components) = if c.peek() == Some(b'(') {
        ("tuple".to_owned(), params_list(c)?)
    } else {
        let base = c.ident().ok_or_else(|| format!("expected a type at position {}", c.i))?;
        let save = c.i;
        c.ws();
        if base == "tuple" && c.peek() == Some(b'(') {
            ("tuple".to_owned(), params_list(c)?)
        } else {
            c.i = save;
            (base.to_owned(), Vec::new())
        }
    };
    let mut ty = ty;
    while c.eat(b'[') {
        let start = c.i;
        while c.peek().is_some_and(|b| b.is_ascii_digit()) {
            c.i += 1;
        }
        let digits = std::str::from_utf8(&c.s[start..c.i]).unwrap_or_default().to_owned();
        c.expect(b']')?;
        ty = format!("{ty}[{digits}]");
    }
    c.ws();
    let mut name = String::new();
    if let Some(word) = c.ident() {
        if matches!(word, "calldata" | "memory" | "storage" | "indexed") {
            c.ws();
            name = c.ident().unwrap_or_default().to_owned();
        } else {
            name = word.to_owned();
        }
    }
    Ok(Param { ty, name, components, internal_type: None })
}

/// `name(type name, …)` for a parsed function.
pub fn canonical(function: &Function) -> Result<String, String> {
    Ok(format!("{}({})", function.name, params(&function.inputs)?))
}

fn params(params: &[Param]) -> Result<String, String> {
    let parts: Result<Vec<String>, String> =
        params.iter().map(|p| -> Result<String, String> { Ok(format!("{} {}", canonical_type(p)?, p.name)) }).collect();
    Ok(parts?.join(", "))
}

fn canonical_type(param: &Param) -> Result<String, String> {
    if let Some(suffix) = param.ty.strip_prefix("tuple") {
        if !is_array_suffix(suffix) {
            return Err(format!("unsupported type {}", param.ty));
        }
        return Ok(format!("({}){suffix}", params(&param.components)?));
    }
    let ty = DynSolType::parse(&param.ty).map_err(|_| format!("unsupported type {}", param.ty))?;
    if contains_function(&ty) {
        return Err("the function type is not supported as an argument".into());
    }
    Ok(ty.sol_type_name().into_owned())
}

fn contains_function(ty: &DynSolType) -> bool {
    match ty {
        DynSolType::Function => true,
        DynSolType::Array(inner) | DynSolType::FixedArray(inner, _) => contains_function(inner),
        DynSolType::Tuple(inner) => inner.iter().any(contains_function),
        _ => false,
    }
}

/// `[]`, `[3]`, `[][2]`… or nothing.
fn is_array_suffix(suffix: &str) -> bool {
    let mut rest = suffix;
    while !rest.is_empty() {
        let Some(inner) = rest.strip_prefix('[') else { return false };
        let Some(end) = inner.find(']') else { return false };
        if !inner[..end].bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        rest = &inner[end + 1..];
    }
    true
}

fn check_names(params: &[Param], top_level: bool) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for (i, p) in params.iter().enumerate() {
        if p.name.is_empty() {
            let what = if top_level { "parameter" } else { "tuple component" };
            return Err(format!(
                "{what} {i} ({}) has no name; every parameter needs one, because wallets show it as the argument's label",
                p.ty
            ));
        }
        if is_solidity_keyword(&p.name) {
            return Err(format!("\"{}\" is a Solidity keyword and cannot be a parameter name", p.name));
        }
        if !seen.insert(p.name.as_str()) {
            return Err(format!("parameter name \"{}\" is used twice", p.name));
        }
        check_names(&p.components, false)?;
    }
    Ok(())
}

/// abitype's `isSolidityKeyword`: names it refuses to parse.
fn is_solidity_keyword(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "address",
        "bool",
        "function",
        "string",
        "tuple",
        "after",
        "alias",
        "anonymous",
        "apply",
        "auto",
        "byte",
        "calldata",
        "case",
        "catch",
        "constant",
        "copyof",
        "default",
        "defined",
        "error",
        "event",
        "external",
        "false",
        "final",
        "immutable",
        "implements",
        "in",
        "indexed",
        "inline",
        "internal",
        "let",
        "mapping",
        "match",
        "memory",
        "mutable",
        "null",
        "of",
        "override",
        "partial",
        "private",
        "promise",
        "public",
        "pure",
        "reference",
        "relocatable",
        "return",
        "returns",
        "sizeof",
        "static",
        "storage",
        "struct",
        "super",
        "supports",
        "switch",
        "this",
        "true",
        "try",
        "typedef",
        "typeof",
        "var",
        "view",
        "virtual",
    ];
    if KEYWORDS.contains(&name) {
        return true;
    }
    let sized = |prefix: &str, valid: fn(u32) -> bool| {
        name.strip_prefix(prefix).is_some_and(|n| n.is_empty() || (!n.starts_with('0') && n.parse().is_ok_and(valid)))
    };
    sized("bytes", |n| (1..=32).contains(&n))
        || sized("uint", |n| n % 8 == 0 && (8..=256).contains(&n))
        || sized("int", |n| n % 8 == 0 && (8..=256).contains(&n))
}

/// The resolved types of a function's inputs, for decoding and encoding its arguments.
pub fn input_types(function: &Function) -> Result<Vec<DynSolType>, String> {
    function.inputs.iter().map(|p| p.resolve().map_err(|e| format!("unsupported type {}: {e}", p.ty))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_signatures() {
        for sig in [
            "deposit(uint256 assets, address receiver)",
            "approve(address spender, uint256 amount)",
            "supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)",
            "fill((address maker, uint256 amount)[] orders, bytes32 id)",
            "notify()",
            "set(uint256[2][] grid, bytes data, string note, bool flag, int128 delta)",
        ] {
            let f = parse(sig).unwrap_or_else(|e| panic!("{sig}: {e}"));
            assert_eq!(canonical(&f).unwrap(), sig);
        }
        assert_eq!(parse("deposit(uint256 assets, address receiver)").unwrap().selector().to_string(), "0x6e553f65");
        // Tuple components are named in the signature, but the selector hashes their types only.
        let fill = parse("fill((address maker, uint256 amount)[] orders, bytes32 id)").unwrap();
        let expected = alloy_primitives::keccak256("fill((address,uint256)[],bytes32)");
        assert_eq!(fill.selector().as_slice(), &expected[..4]);
    }

    #[test]
    fn names_the_canonical_form_for_everything_else() {
        let err = |sig: &str| parse(sig).unwrap_err();
        let want = "write it exactly as \"deposit(uint256 assets, address receiver)\"";
        assert!(err("function deposit(uint256 assets, address receiver)").starts_with(want));
        assert!(err("deposit(uint256 assets, address receiver) returns (uint256 shares)").starts_with(want));
        assert!(err("deposit(uint256 assets, address receiver) external view").starts_with(want));
        assert!(err("deposit(uint256 calldata assets, address receiver)").starts_with(want));
        assert!(err("deposit(uint assets, address receiver)").starts_with(want));
        assert!(err("deposit(uint256 assets,address receiver)").starts_with(want));
        assert!(err(" deposit(uint256 assets, address receiver)").starts_with(want));
        assert!(
            err("fill(tuple(address maker, uint256 amount)[] orders, bytes32 id)")
                .starts_with("write it exactly as \"fill((address maker, uint256 amount)[] orders, bytes32 id)\"")
        );
    }

    #[test]
    fn every_parameter_needs_a_unique_non_keyword_name() {
        assert!(parse("deposit(uint256, address)").unwrap_err().contains("has no name"));
        assert!(parse("f((uint256, address b) t)").unwrap_err().contains("tuple component 0"));
        assert!(parse("f(uint256 a, address a)").unwrap_err().contains("used twice"));
        assert!(parse("f(address address)").unwrap_err().contains("Solidity keyword"));
        assert!(parse("f(uint256 uint8)").unwrap_err().contains("Solidity keyword"));
        assert!(parse("f(uint256 uint7)").is_ok(), "not a real type, so not a keyword");
        assert!(parse("f(uint256 bytes33)").is_ok());
    }

    #[test]
    fn rejects_what_cannot_be_an_argument() {
        assert!(parse("f(function cb)").is_err());
        assert!(parse("not a signature").unwrap_err().starts_with("not a Solidity function signature"));
    }
}
