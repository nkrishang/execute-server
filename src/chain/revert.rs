//! Why a settlement reverted, decoded from `PaymentFactory.execute`'s revert data.
//!
//! `execute` deploys the `Payment` with CREATE2 and passes on the constructor's revert data
//! unchanged, and the constructor wraps a failing settlement call's own revert data in
//! `CallFailed(index, revertData)`. So the bytes gum-engine reports when its simulation of
//! `execute` reverts say exactly what went wrong, down to the token's own reason:
//!
//! ```text
//! CallFailed(0, Error("Blacklistable: account is blacklisted"))
//! ```
//!
//! Decoding is best effort. `Payment`'s and `PaymentFactory`'s errors are known exactly; a call
//! target's reason is decoded when it is a Solidity `Error(string)` or `Panic(uint256)`, or one of
//! the custom errors below that the registry's tokens are known to use. Anything else is kept as
//! an unrecognised error with its selector.
//!
//! Apps get [`RevertView`]: every level, the call's own reason included, carries its raw bytes, so
//! an app can always decode them against ABIs we do not know.

use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolError, SolInterface, sol};
use serde::{Deserialize, Serialize};

use super::payment::{Call, IERC20};

sol! {
    /// gum-contracts `Payment` constructor errors, passed on by `PaymentFactory.execute`.
    interface IPaymentErrors {
        error InsufficientTokenBalance(uint256 balance, uint256 required);
        error CallFailed(uint256 index, bytes revertData);
        error CallTargetHasNoCode(uint256 index, address target);
        error AmountNotSpent(uint256 remaining);
    }

    /// gum-contracts `PaymentFactory` errors.
    interface IPaymentFactoryErrors {
        error AlreadyDeployed();
        error DeploymentFailed();
        error InitCodeTooLarge(uint256 length);
    }

    /// Custom errors settlement call targets are known to revert with. Tokens that revert with a
    /// string (Circle's FiatToken, Tether's USDT0) need no entry: `Error(string)` covers them.
    interface ICallTargetErrors {
        // OpenZeppelin v5 `IERC20Errors`, e.g. AgoraDollar (AUSD).
        error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
        error ERC20InvalidSender(address sender);
        error ERC20InvalidReceiver(address receiver);
        error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
        error ERC20InvalidApprover(address approver);
        error ERC20InvalidSpender(address spender);
        // OpenZeppelin v5 `Pausable`.
        error EnforcedPause();
        // AgoraDollar (AUSD).
        error AccountIsFrozen(address frozenAccount);
        error TransferPaused();
        // Solady `ERC20` (gum-contracts' local MockStablecoin).
        error InsufficientBalance();
        error InsufficientAllowance();
        // Solady `SafeTransferLib`. `Payment` itself reverts with `TransferFailed` when forwarding
        // the excess or an expired balance to recovery fails.
        error TransferFailed();
        error TransferFromFailed();
        error ApproveFailed();
    }
}

/// A decoded revert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// `Payment`: the address holds less than the amount it settles.
    InsufficientTokenBalance { balance: U256, required: U256 },
    /// `Payment`: settlement call `index` reverted with `revert_data`, the target's own revert,
    /// decoded as `reason`.
    CallFailed { index: U256, revert_data: Bytes, reason: Box<Reason> },
    /// `Payment`: settlement call `index` targets an address with no code.
    CallTargetHasNoCode { index: U256, target: Address },
    /// `Payment`: the calls succeeded but left `remaining` of the amount unspent.
    AmountNotSpent { remaining: U256 },
    /// `PaymentFactory`: the payment was already executed.
    AlreadyDeployed,
    /// `PaymentFactory`: the constructor reverted without data (e.g. out of gas).
    DeploymentFailed,
    /// `PaymentFactory`: the encoded terms exceed EIP-3860's 49,152-byte init-code limit.
    InitCodeTooLarge { length: U256 },
    /// `Error(string)`: `require(…, "reason")` or `revert("reason")`.
    Message(String),
    /// `Panic(uint256)`: a failed assert, arithmetic overflow, out-of-bounds index, …
    Panic(U256),
    /// One of [`ICallTargetErrors`], with its arguments as [`RevertView::args`] renders them.
    Custom { signature: &'static str, args: Vec<(&'static str, String)> },
    /// Reverted without data.
    Empty,
    /// Data we cannot decode: an error we do not know, or a truncated one.
    Unrecognised(Bytes),
}

/// Decodes the revert data of `PaymentFactory.execute`.
pub fn decode_execute(data: &[u8]) -> Reason {
    if let Ok(error) = IPaymentErrors::IPaymentErrorsErrors::abi_decode(data) {
        use IPaymentErrors::IPaymentErrorsErrors as E;
        return match error {
            E::InsufficientTokenBalance(e) => {
                Reason::InsufficientTokenBalance { balance: e.balance, required: e.required }
            }
            E::CallFailed(e) => Reason::CallFailed {
                index: e.index,
                reason: Box::new(decode_call(&e.revertData)),
                revert_data: e.revertData,
            },
            E::CallTargetHasNoCode(e) => Reason::CallTargetHasNoCode { index: e.index, target: e.target },
            E::AmountNotSpent(e) => Reason::AmountNotSpent { remaining: e.remaining },
        };
    }
    if let Ok(error) = IPaymentFactoryErrors::IPaymentFactoryErrorsErrors::abi_decode(data) {
        use IPaymentFactoryErrors::IPaymentFactoryErrorsErrors as E;
        return match error {
            E::AlreadyDeployed(_) => Reason::AlreadyDeployed,
            E::DeploymentFailed(_) => Reason::DeploymentFailed,
            E::InitCodeTooLarge(e) => Reason::InitCodeTooLarge { length: e.length },
        };
    }
    decode_call(data)
}

/// Decodes the revert data of a settlement call's target (or of anything else `Payment` calls).
pub fn decode_call(data: &[u8]) -> Reason {
    if data.is_empty() {
        return Reason::Empty;
    }
    if let Ok(e) = alloy_sol_types::Revert::abi_decode(data) {
        return Reason::Message(sanitize(e.reason));
    }
    if let Ok(e) = alloy_sol_types::Panic::abi_decode(data) {
        return Reason::Panic(e.code);
    }
    let Ok(error) = ICallTargetErrors::ICallTargetErrorsErrors::abi_decode(data) else {
        return Reason::Unrecognised(Bytes::copy_from_slice(data));
    };
    use ICallTargetErrors::{ICallTargetErrorsErrors as E, *};
    fn custom<T: SolError>(args: Vec<(&'static str, String)>) -> Reason {
        Reason::Custom { signature: T::SIGNATURE, args }
    }
    match error {
        E::ERC20InsufficientBalance(e) => custom::<ERC20InsufficientBalance>(vec![
            ("sender", address(e.sender)),
            ("balance", e.balance.to_string()),
            ("needed", e.needed.to_string()),
        ]),
        E::ERC20InvalidSender(e) => custom::<ERC20InvalidSender>(vec![("sender", address(e.sender))]),
        E::ERC20InvalidReceiver(e) => custom::<ERC20InvalidReceiver>(vec![("receiver", address(e.receiver))]),
        E::ERC20InsufficientAllowance(e) => custom::<ERC20InsufficientAllowance>(vec![
            ("spender", address(e.spender)),
            ("allowance", e.allowance.to_string()),
            ("needed", e.needed.to_string()),
        ]),
        E::ERC20InvalidApprover(e) => custom::<ERC20InvalidApprover>(vec![("approver", address(e.approver))]),
        E::ERC20InvalidSpender(e) => custom::<ERC20InvalidSpender>(vec![("spender", address(e.spender))]),
        E::EnforcedPause(_) => custom::<EnforcedPause>(vec![]),
        E::AccountIsFrozen(e) => custom::<AccountIsFrozen>(vec![("frozenAccount", address(e.frozenAccount))]),
        E::TransferPaused(_) => custom::<TransferPaused>(vec![]),
        E::InsufficientBalance(_) => custom::<InsufficientBalance>(vec![]),
        E::InsufficientAllowance(_) => custom::<InsufficientAllowance>(vec![]),
        E::TransferFailed(_) => custom::<TransferFailed>(vec![]),
        E::TransferFromFailed(_) => custom::<TransferFromFailed>(vec![]),
        E::ApproveFailed(_) => custom::<ApproveFailed>(vec![]),
    }
}

impl Reason {
    /// The Solidity error's signature, e.g. `CallFailed(uint256,bytes)`; `None` when there is no
    /// error to name (empty or unrecognised).
    pub fn signature(&self) -> Option<&'static str> {
        Some(match self {
            Self::InsufficientTokenBalance { .. } => IPaymentErrors::InsufficientTokenBalance::SIGNATURE,
            Self::CallFailed { .. } => IPaymentErrors::CallFailed::SIGNATURE,
            Self::CallTargetHasNoCode { .. } => IPaymentErrors::CallTargetHasNoCode::SIGNATURE,
            Self::AmountNotSpent { .. } => IPaymentErrors::AmountNotSpent::SIGNATURE,
            Self::AlreadyDeployed => IPaymentFactoryErrors::AlreadyDeployed::SIGNATURE,
            Self::DeploymentFailed => IPaymentFactoryErrors::DeploymentFailed::SIGNATURE,
            Self::InitCodeTooLarge { .. } => IPaymentFactoryErrors::InitCodeTooLarge::SIGNATURE,
            Self::Message(_) => alloy_sol_types::Revert::SIGNATURE,
            Self::Panic(_) => alloy_sol_types::Panic::SIGNATURE,
            Self::Custom { signature, .. } => signature,
            Self::Empty | Self::Unrecognised(_) => return None,
        })
    }

    /// The Solidity error's name, e.g. `CallFailed`.
    pub fn name(&self) -> Option<&'static str> {
        self.signature().map(|s| s.split('(').next().expect("split yields at least one item"))
    }

    /// The error's arguments, every value a string: `uint`s in decimal, addresses as lowercase
    /// `0x` hex, strings as they are. `CallFailed`'s `revertData` is not among them: it is the
    /// nested reason.
    fn args(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::InsufficientTokenBalance { balance, required } => {
                vec![("balance", balance.to_string()), ("required", required.to_string())]
            }
            Self::CallFailed { index, .. } => vec![("index", index.to_string())],
            Self::CallTargetHasNoCode { index, target } => {
                vec![("index", index.to_string()), ("target", address(*target))]
            }
            Self::AmountNotSpent { remaining } => vec![("remaining", remaining.to_string())],
            Self::Message(message) => vec![("message", message.clone())],
            Self::Panic(code) => vec![("code", code.to_string())],
            Self::Custom { args, .. } => args.clone(),
            Self::InitCodeTooLarge { length } => vec![("length", length.to_string())],
            Self::AlreadyDeployed | Self::DeploymentFailed | Self::Empty | Self::Unrecognised(_) => vec![],
        }
    }

    /// A bounded label for metrics: the error's name, `empty` or `unrecognised`, and for
    /// `CallFailed` the call's reason too (`CallFailed:Error`).
    pub fn label(&self) -> String {
        let name = |r: &Reason| match r {
            Self::Empty => "empty",
            Self::Unrecognised(_) => "unrecognised",
            other => other.name().expect("named"),
        };
        match self {
            Self::CallFailed { reason, .. } => format!("CallFailed:{}", name(reason)),
            other => name(other).to_owned(),
        }
    }

    /// One sentence saying what went wrong, for `failure.message`. `calls` are the deposit's
    /// settlement calls, which the call index refers to.
    pub fn describe(&self, calls: &[Call]) -> String {
        match self {
            Self::InsufficientTokenBalance { balance, required } => {
                format!("the payment address holds {balance}, less than the {required} it settles")
            }
            Self::CallFailed { index, reason, .. } => {
                format!("settlement {} reverted: {}", describe_call(*index, calls), reason.describe_call_reason())
            }
            Self::CallTargetHasNoCode { index, target } => {
                format!("settlement call {index} targets {target:#x}, which has no code on this chain")
            }
            Self::AmountNotSpent { remaining } => format!(
                "the settlement calls succeeded but left {remaining} of the amount unspent \
                 (a token that returns false instead of reverting does this)"
            ),
            Self::AlreadyDeployed => "the payment was already executed: an earlier execute went through, and its \
                 receipt says whether it settled or went to recovery"
                .to_owned(),
            Self::DeploymentFailed => "the Payment constructor reverted without data (e.g. out of gas)".to_owned(),
            Self::InitCodeTooLarge { length } => {
                format!("the encoded payment terms are {length} bytes, past EIP-3860's 49,152-byte init-code limit")
            }
            Self::Custom { signature, .. } if *signature == ICallTargetErrors::TransferFailed::SIGNATURE => {
                "the payment's own transfer of the token to the recovery address failed".to_owned()
            }
            other => format!("reverted: {}", other.describe_call_reason()),
        }
    }

    /// A call target's reason, as it reads after "reverted: ".
    fn describe_call_reason(&self) -> String {
        match self {
            Self::Message(message) => message.clone(),
            Self::Panic(code) => match u32::try_from(*code).ok().and_then(alloy_sol_types::PanicKind::from_number) {
                Some(kind) => format!("panic {code:#x} ({kind})"),
                None => format!("panic {code:#x}"),
            },
            Self::Custom { .. } => {
                let args: Vec<String> = self.args().iter().map(|(k, v)| format!("{k}: {v}")).collect();
                format!("{}({})", self.name().expect("named"), args.join(", "))
            }
            Self::Empty => "no reason given".to_owned(),
            Self::Unrecognised(data) if data.len() >= 4 => {
                format!("an unrecognised error (selector 0x{})", hex::encode(&data[..4]))
            }
            Self::Unrecognised(data) => format!("unrecognised data {data}"),
            // Payment's own errors never come from a call target; describe them in full.
            other => other.describe(&[]),
        }
    }
}

/// How far a revert could be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertKind {
    /// A known error: `name`, `signature` and `args` are set.
    Decoded,
    /// No revert data at all.
    Empty,
    /// Data we cannot decode: `selector` is set when there are at least four bytes.
    Unrecognised,
}

/// `failure.revert`: one level of revert data, decoded as far as we can, with its raw bytes.
/// For `CallFailed`, `reason` is the call's own revert in the same shape, so an app gets the
/// token's raw revert data as `reason.data` without decoding `CallFailed` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevertView {
    pub kind: RevertKind,
    /// The raw revert data of this level, `0x` hex.
    pub data: String,
    /// The first four bytes of `data`, `0x` hex: the error's selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// e.g. `CallFailed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// e.g. `CallFailed(uint256,bytes)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The error's arguments by name, every value a string: `uint`s in decimal, addresses as
    /// lowercase `0x` hex, strings as they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<BTreeMap<String, String>>,
    /// `CallFailed` and `CallTargetHasNoCode`: the deposit's settlement call the error is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<CallRef>,
    /// `CallFailed`: the call's own revert (its `revertData`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Box<RevertView>>,
}

/// A settlement call, by its position in the deposit's `calls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRef {
    pub index: u64,
    pub target: String,
}

impl RevertView {
    /// `failure.revert` for `execute`'s revert `data`; `calls` are the deposit's settlement calls.
    pub fn of_execute(data: &[u8], calls: &[Call]) -> Self {
        Self::of(data, &decode_execute(data), calls)
    }

    fn of(data: &[u8], reason: &Reason, calls: &[Call]) -> Self {
        let kind = match reason {
            Reason::Empty => RevertKind::Empty,
            Reason::Unrecognised(_) => RevertKind::Unrecognised,
            _ => RevertKind::Decoded,
        };
        let call = match reason {
            Reason::CallFailed { index, .. } | Reason::CallTargetHasNoCode { index, .. } => {
                call_at(*index, calls).map(|call| CallRef {
                    index: u64::try_from(*index).expect("an index into calls fits u64"),
                    target: address(call.target),
                })
            }
            _ => None,
        };
        Self {
            kind,
            data: format!("0x{}", hex::encode(data)),
            selector: (data.len() >= 4).then(|| format!("0x{}", hex::encode(&data[..4]))),
            name: reason.name().map(str::to_owned),
            signature: reason.signature().map(str::to_owned),
            args: (kind == RevertKind::Decoded)
                .then(|| reason.args().into_iter().map(|(k, v)| (k.to_owned(), v)).collect()),
            call,
            // A call's own revert never refers to the deposit's calls.
            reason: match reason {
                Reason::CallFailed { revert_data, reason, .. } => Some(Box::new(Self::of(revert_data, reason, &[]))),
                _ => None,
            },
        }
    }
}

fn address(a: Address) -> String {
    format!("{a:#x}")
}

/// A token's revert string is arbitrary: a `U+0000` in it would reach `failure.message` (a
/// PostgreSQL `TEXT`) and `revert.args` (`JSONB`), both of which reject NUL, so recording the
/// failure would fail on every attempt. Render it escaped; the raw bytes stay intact in
/// `RevertView`'s `data`.
fn sanitize(message: String) -> String {
    message.replace('\0', "\\0")
}

fn call_at(index: U256, calls: &[Call]) -> Option<&Call> {
    usize::try_from(index).ok().and_then(|i| calls.get(i))
}

/// "call 0 (transfer of 2500000 to 0x…)" for a token transfer; "call 0 (to 0x…)" otherwise.
fn describe_call(index: U256, calls: &[Call]) -> String {
    let Some(call) = call_at(index, calls) else { return format!("call {index}") };
    match IERC20::transferCall::abi_decode(&call.data) {
        Ok(t) => format!("call {index} (transfer of {} to {:#x})", t.amount, t.to),
        Err(_) => format!("call {index} (to {:#x})", call.target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, hex};
    use serde_json::json;

    const USDC: Address = address!("e7f1725E7734CE288F8367e1Bb143E90bb3F0512");
    const RECEIVER: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

    fn calls() -> Vec<Call> {
        vec![Call::transfer(USDC, RECEIVER, U256::from(2_500_000u64))]
    }

    fn describe(data: &[u8]) -> String {
        decode_execute(data).describe(&calls())
    }

    // Revert data returned by `eth_estimateGas` for `PaymentFactory.execute` on Anvil, with the
    // gum-contracts PR #1 factory and MockStablecoin deployed by LocalBootstrap: exactly what
    // gum-engine relays when its simulation reverts.
    const UNDERFUNDED: &[u8] = &hex!(
        "a17124f800000000000000000000000000000000000000000000000000000000000f424000000000000000000000000000000000000000000000000000000000002625a0"
    );
    const BLACKLISTED: &[u8] = &hex!(
        "5c0dee5d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008408c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000025426c61636b6c69737461626c653a206163636f756e7420697320626c61636b6c697374656400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    const PAUSED: &[u8] = &hex!(
        "5c0dee5d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006408c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000105061757361626c653a207061757365640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    const OVERSPENT: &[u8] = &hex!(
        "5c0dee5d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004f4d678b800000000000000000000000000000000000000000000000000000000"
    );
    const UNDERSPENT: &[u8] = &hex!("e58991f10000000000000000000000000000000000000000000000000000000000000001");
    const NO_CODE: &[u8] = &hex!(
        "5dcee19d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090f79bf6eb2c4f870365e785982e1f101e93b906"
    );
    const ALREADY_EXECUTED: &[u8] = &hex!("a6ef0ba1");
    const EXCESS_TO_RECOVERY_FAILED: &[u8] = &hex!("90b8ec18");

    #[test]
    fn payment_errors_from_a_real_factory() {
        assert_eq!(
            decode_execute(UNDERFUNDED),
            Reason::InsufficientTokenBalance { balance: U256::from(1_000_000u64), required: U256::from(2_500_000u64) }
        );
        assert_eq!(describe(UNDERFUNDED), "the payment address holds 1000000, less than the 2500000 it settles");

        assert_eq!(decode_execute(UNDERSPENT), Reason::AmountNotSpent { remaining: U256::from(1u64) });
        assert!(describe(UNDERSPENT).starts_with("the settlement calls succeeded but left 1 of the amount unspent"));

        let eoa = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");
        assert_eq!(decode_execute(NO_CODE), Reason::CallTargetHasNoCode { index: U256::ZERO, target: eoa });
        assert_eq!(
            describe(NO_CODE),
            "settlement call 0 targets 0x90f79bf6eb2c4f870365e785982e1f101e93b906, which has no code on this chain"
        );

        assert_eq!(decode_execute(ALREADY_EXECUTED), Reason::AlreadyDeployed);
        assert!(describe(ALREADY_EXECUTED).starts_with("the payment was already executed"));

        assert_eq!(
            decode_execute(EXCESS_TO_RECOVERY_FAILED),
            Reason::Custom { signature: "TransferFailed()", args: vec![] }
        );
        assert_eq!(
            describe(EXCESS_TO_RECOVERY_FAILED),
            "the payment's own transfer of the token to the recovery address failed"
        );

        let too_large = IPaymentFactoryErrors::InitCodeTooLarge { length: U256::from(49_153u64) }.abi_encode();
        assert_eq!(decode_execute(&too_large), Reason::InitCodeTooLarge { length: U256::from(49_153u64) });
        assert_eq!(decode_execute(&too_large).label(), "InitCodeTooLarge");
        assert_eq!(
            describe(&too_large),
            "the encoded payment terms are 49153 bytes, past EIP-3860's 49,152-byte init-code limit"
        );
    }

    #[test]
    fn a_failed_call_carries_the_tokens_own_reason() {
        assert_eq!(
            decode_execute(BLACKLISTED),
            Reason::CallFailed {
                index: U256::ZERO,
                revert_data: alloy_sol_types::Revert::from("Blacklistable: account is blacklisted").abi_encode().into(),
                reason: Box::new(Reason::Message("Blacklistable: account is blacklisted".into()))
            }
        );
        assert_eq!(
            describe(BLACKLISTED),
            "settlement call 0 (transfer of 2500000 to 0x70997970c51812dc3a010c7d01b50e0d17dc79c8) reverted: \
             Blacklistable: account is blacklisted"
        );
        assert!(describe(PAUSED).ends_with("reverted: Pausable: paused"));
        assert!(describe(OVERSPENT).ends_with("reverted: InsufficientBalance()"), "Solady ERC20");
    }

    fn call_failed(index: u64, revert_data: Vec<u8>) -> Vec<u8> {
        IPaymentErrors::CallFailed { index: U256::from(index), revertData: revert_data.into() }.abi_encode()
    }

    #[test]
    fn custom_token_errors_panics_and_the_unknown() {
        // Monad AUSD (AgoraDollar, OpenZeppelin v5), observed via eth_call of transfer(…, 1000000)
        // from an address holding none.
        let ausd = hex!(
            "e450d38c"
            "0000000000000000000000001111111111111111111111111111111111111112"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000f4240"
        );
        assert_eq!(
            describe(&call_failed(0, ausd.to_vec())),
            "settlement call 0 (transfer of 2500000 to 0x70997970c51812dc3a010c7d01b50e0d17dc79c8) reverted: \
             ERC20InsufficientBalance(sender: 0x1111111111111111111111111111111111111112, balance: 0, needed: 1000000)"
        );
        // Arc USDC (FiatToken over the native balance, at 0x3600…), observed on Arc mainnet via eth_call
        // of transfer(…, 1000000) from an address holding none: a plain Error(string).
        let arc_usdc = hex!(
            "08c379a0"
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000026"
            "45524332303a207472616e7366657220616d6f756e7420657863656564732062"
            "616c616e63650000000000000000000000000000000000000000000000000000"
        );
        assert!(
            describe(&call_failed(0, arc_usdc.to_vec())).ends_with("reverted: ERC20: transfer amount exceeds balance")
        );
        let frozen = ICallTargetErrors::AccountIsFrozen { frozenAccount: RECEIVER }.abi_encode();
        assert!(
            describe(&call_failed(0, frozen))
                .ends_with("AccountIsFrozen(frozenAccount: 0x70997970c51812dc3a010c7d01b50e0d17dc79c8)")
        );

        let overflow = alloy_sol_types::Panic { code: U256::from(0x11) }.abi_encode();
        assert!(
            describe(&call_failed(0, overflow)).ends_with("reverted: panic 0x11 (arithmetic underflow or overflow)")
        );
        assert!(describe(&call_failed(0, vec![])).ends_with("reverted: no reason given"));
        assert!(
            describe(&call_failed(0, hex!("deadbeef00").to_vec()))
                .ends_with("an unrecognised error (selector 0xdeadbeef)")
        );
        // A call index past the list (never from our own calls) still reads.
        assert!(describe(&call_failed(7, vec![])).starts_with("settlement call 7 reverted"));

        // Outside CallFailed: an unknown top-level error, a bare string, no data at all.
        assert_eq!(describe(&hex!("12345678")), "reverted: an unrecognised error (selector 0x12345678)");
        assert_eq!(describe(&alloy_sol_types::Revert::from("nope").abi_encode()), "reverted: nope");
        assert_eq!(decode_execute(&[]), Reason::Empty);
        assert_eq!(describe(&hex!("00")), "reverted: unrecognised data 0x00");
    }

    /// A NUL in a revert string must not reach `failure.message` (`TEXT`) or `revert.args`
    /// (`JSONB`): PostgreSQL rejects it, and the failure would never be recorded.
    #[test]
    fn a_nul_in_a_revert_string_is_escaped_not_stored_raw() {
        let inner = alloy_sol_types::Revert::from("bad\0reason").abi_encode();
        let reason = decode_execute(&call_failed(0, inner.clone()));
        assert_eq!(
            reason,
            Reason::CallFailed {
                index: U256::ZERO,
                revert_data: inner.clone().into(),
                reason: Box::new(Reason::Message("bad\\0reason".into()))
            }
        );
        assert!(!describe(&call_failed(0, inner.clone())).contains('\0'));

        // The raw bytes the app decodes against its own ABIs are untouched.
        let view = serde_json::to_value(RevertView::of_execute(&call_failed(0, inner.clone()), &calls())).unwrap();
        assert_eq!(view["reason"]["args"]["message"], "bad\\0reason");
        assert_eq!(view["reason"]["data"], format!("0x{}", hex::encode(inner)));
    }

    #[test]
    fn a_truncated_reason_is_kept_as_unrecognised() {
        // Payment caps a call's revert data at 0xffff bytes, so a long reason may not decode.
        let mut long = alloy_sol_types::Revert::from("x".repeat(100)).abi_encode();
        long.truncate(80);
        let reason = decode_execute(&call_failed(0, long.clone()));
        assert_eq!(
            reason,
            Reason::CallFailed {
                index: U256::ZERO,
                revert_data: long.clone().into(),
                reason: Box::new(Reason::Unrecognised(long.into()))
            }
        );
        assert_eq!(reason.label(), "CallFailed:unrecognised");
    }

    fn view(data: &[u8]) -> serde_json::Value {
        serde_json::to_value(RevertView::of_execute(data, &calls())).unwrap()
    }

    /// The wire format apps depend on.
    #[test]
    fn the_view_is_typed_and_carries_raw_data_at_every_level() {
        let inner = format!(
            "0x{}",
            hex::encode(alloy_sol_types::Revert::from("Blacklistable: account is blacklisted").abi_encode())
        );
        assert_eq!(
            view(BLACKLISTED),
            json!({
                "kind": "decoded",
                "data": format!("0x{}", hex::encode(BLACKLISTED)),
                "selector": "0x5c0dee5d",
                "name": "CallFailed",
                "signature": "CallFailed(uint256,bytes)",
                "args": { "index": "0" },
                "call": { "index": 0, "target": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512" },
                "reason": {
                    "kind": "decoded",
                    "data": inner,
                    "selector": "0x08c379a0",
                    "name": "Error",
                    "signature": "Error(string)",
                    "args": { "message": "Blacklistable: account is blacklisted" },
                },
            })
        );
        assert_eq!(
            view(OVERSPENT)["reason"],
            json!({
                "kind": "decoded", "data": "0xf4d678b8", "selector": "0xf4d678b8",
                "name": "InsufficientBalance", "signature": "InsufficientBalance()", "args": {},
            }),
            "a decoded error with no arguments still has args"
        );
        assert_eq!(
            view(UNDERFUNDED),
            json!({
                "kind": "decoded",
                "data": format!("0x{}", hex::encode(UNDERFUNDED)),
                "selector": "0xa17124f8",
                "name": "InsufficientTokenBalance",
                "signature": "InsufficientTokenBalance(uint256,uint256)",
                "args": { "balance": "1000000", "required": "2500000" },
            })
        );
        assert_eq!(
            view(NO_CODE)["call"],
            json!({ "index": 0, "target": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512" })
        );
        let unknown = call_failed(0, hex!("deadbeef0001").to_vec());
        assert_eq!(
            view(&unknown)["reason"],
            json!({ "kind": "unrecognised", "data": "0xdeadbeef0001", "selector": "0xdeadbeef" }),
            "an app can decode the call's raw revert against its own ABIs"
        );
        assert_eq!(view(&call_failed(0, vec![]))["reason"], json!({ "kind": "empty", "data": "0x" }));
        assert_eq!(view(&[]), json!({ "kind": "empty", "data": "0x" }));
        assert_eq!(view(&hex!("00")), json!({ "kind": "unrecognised", "data": "0x00" }));

        // Clients can deserialize what we serve.
        let typed: RevertView = serde_json::from_value(view(BLACKLISTED)).unwrap();
        assert_eq!(typed, RevertView::of_execute(BLACKLISTED, &calls()));
        assert_eq!(typed.reason.unwrap().kind, RevertKind::Decoded);
    }

    #[test]
    fn labels_are_bounded() {
        assert_eq!(decode_execute(BLACKLISTED).label(), "CallFailed:Error");
        assert_eq!(decode_execute(OVERSPENT).label(), "CallFailed:InsufficientBalance");
        assert_eq!(decode_execute(UNDERFUNDED).label(), "InsufficientTokenBalance");
        assert_eq!(decode_execute(ALREADY_EXECUTED).label(), "AlreadyDeployed");
        assert_eq!(decode_execute(&hex!("12345678")).label(), "unrecognised");
        assert_eq!(decode_execute(&[]).label(), "empty");
    }
}
