//! `PaymentFactory` address derivation and calldata, reproduced offchain so creating an address never
//! touches an RPC.
//!
//! ```text
//! terms          = abi.encode(token, amount, calls, expirationTimestamp, recovery, salt, chainId)
//! implementation = CREATE(factory, nonce = 1)
//! initCode       = Payment.creationCode ++ abi.encode(implementation, terms)
//! address        = CREATE2(factory, bytes32(0), keccak256(initCode))
//! ```
//!
//! `terms` is exactly the calldata arguments of `paymentAddress` and `execute`. `Payment.creationCode`
//! is pinned in `payment_creation_code.hex` and belongs to one contract generation.

use std::sync::LazyLock;

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolEvent, SolValue, sol};

sol! {
    /// gum-contracts `Payment.Call`: one call the payment makes, as itself, on settlement.
    #[derive(Debug, PartialEq, Eq)]
    struct Call {
        address target;
        bytes data;
    }

    /// gum-contracts `PaymentFactory`.
    interface IPaymentFactory {
        function execute(
            address token,
            uint256 amount,
            Call[] calls,
            uint64 expirationTimestamp,
            address recovery,
            bytes32 salt,
            uint256 chainId
        ) external;
    }

    /// gum-contracts `Payment` events, emitted by the executable address during `execute`.
    interface IPayment {
        event Settled(address indexed token, uint256 amount);
        event Recovered(address indexed recovery, address indexed token, uint256 amount);
        event WrongChain(uint256 expectedChainId, uint256 actualChainId);
    }

    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// `type(Payment).creationCode` of the generation this server targets: the `bytecode` of
/// gum-contracts' `out/Payment.sol/Payment.json`.
static PAYMENT_CREATION_CODE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    hex::decode(include_str!("payment_creation_code.hex").trim()).expect("payment_creation_code.hex is valid hex")
});

/// EIP-3860's init code limit; `PaymentFactory` refuses terms beyond it (`InitCodeTooLarge`).
pub const MAX_INIT_CODE_BYTES: usize = 49_152;

impl Call {
    /// `token.transfer(to, amount)`: a plain payment's one call.
    pub fn transfer(token: Address, to: Address, amount: U256) -> Self {
        Self { target: token, data: IERC20::transferCall { to, amount }.abi_encode().into() }
    }
}

/// `PaymentFactory.paymentImplementation()`: `Payment`'s runtime, deployed by the factory's constructor
/// as its first creation. Every payment's stub delegatecalls it.
pub fn payment_implementation(factory: Address) -> Address {
    factory.create(1)
}

/// The seven terms an executable address commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentTerms {
    pub token: Address,
    pub amount: U256,
    /// Run in order on settlement; together they must spend exactly `amount`.
    pub calls: Vec<Call>,
    pub expiration_timestamp: u64,
    pub recovery: Address,
    pub salt: B256,
    pub chain_id: u64,
}

impl PaymentTerms {
    /// `PaymentFactory.paymentAddress(...)` for a factory deployed at `factory`.
    pub fn payment_address(&self, factory: Address) -> Address {
        factory.create2(B256::ZERO, keccak256(self.init_code(factory)))
    }

    /// Calldata for `PaymentFactory.execute(...)`.
    pub fn execute_calldata(&self) -> Bytes {
        IPaymentFactory::executeCall {
            token: self.token,
            amount: self.amount,
            calls: self.calls.clone(),
            expirationTimestamp: self.expiration_timestamp,
            recovery: self.recovery,
            salt: self.salt,
            chainId: U256::from(self.chain_id),
        }
        .abi_encode()
        .into()
    }

    /// `abi.encode(token, amount, calls, expirationTimestamp, recovery, salt, chainId)`: `execute`'s
    /// calldata without its selector, exactly as the factory copies it into the init code.
    pub fn terms(&self) -> Bytes {
        Bytes::copy_from_slice(&self.execute_calldata()[4..])
    }

    /// Length of `Payment.creationCode ++ abi.encode(implementation, terms)`.
    pub fn init_code_len(&self) -> usize {
        let terms = self.terms().len();
        PAYMENT_CREATION_CODE.len() + 0x60 + terms.div_ceil(32) * 32
    }

    /// `Payment.creationCode ++ abi.encode(paymentImplementation(), terms)`.
    fn init_code(&self, factory: Address) -> Vec<u8> {
        let args = (payment_implementation(factory), self.terms()).abi_encode_params();
        [PAYMENT_CREATION_CODE.as_slice(), &args].concat()
    }
}

/// What a `Payment` constructor did, read from the receipt logs of the `execute` transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// `Settled(token, amount)`: every call succeeded and together they spent exactly `amount`. Any
    /// excess went to recovery first, which does not change the outcome.
    Settled,
    /// Only `Recovered`: the payment had expired, so the balance went to recovery.
    Recovered { amount: U256 },
    /// `WrongChain`: cannot happen when gum-engine honours the chain id; kept for completeness.
    WrongChain,
    /// Neither event was found for the address.
    NoEvents,
}

/// A receipt log in the node's JSON encoding (`address`, `topics`, `data`).
#[derive(Debug, serde::Deserialize)]
pub struct ReceiptLog {
    pub address: Address,
    pub topics: Vec<B256>,
    #[serde(default)]
    pub data: Bytes,
}

pub fn execution_outcome(logs: &[ReceiptLog], address: Address) -> ExecutionOutcome {
    let mut recovered: Option<U256> = None;
    for log in logs.iter().filter(|l| l.address == address) {
        let Some(topic0) = log.topics.first() else { continue };
        if *topic0 == IPayment::Settled::SIGNATURE_HASH {
            return ExecutionOutcome::Settled;
        }
        if *topic0 == IPayment::WrongChain::SIGNATURE_HASH {
            return ExecutionOutcome::WrongChain;
        }
        if *topic0 == IPayment::Recovered::SIGNATURE_HASH {
            let amount = U256::abi_decode(&log.data).unwrap_or_default();
            recovered = Some(recovered.unwrap_or_default() + amount);
        }
    }
    match recovered {
        Some(amount) => ExecutionOutcome::Recovered { amount },
        None => ExecutionOutcome::NoEvents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    /// Pins the generation: gum-contracts `5eb28d6`, solc 0.8.33, 1,000,000 optimizer runs, EVM prague.
    #[test]
    fn creation_code_is_the_pinned_generation() {
        assert_eq!(PAYMENT_CREATION_CODE.len(), 2042);
        assert_eq!(
            keccak256(PAYMENT_CREATION_CODE.as_slice()),
            b256!("f876e365d3c4745f0abb25ffcc7fd085b62bbd9cce612b0d6e2218aa772dd783")
        );
    }

    /// Known answer from `PaymentFactory.paymentAddress` on Base (read with `cast call`, 2026-09-24).
    #[test]
    fn matches_the_mainnet_factory() {
        let factory = address!("6D85B9706D8f076cB8A9fEA37d70Fcb8D22C2952");
        assert_eq!(payment_implementation(factory), address!("bB6584608a15ce2574F2a6EaE8F2aCC59cEEa502"));
        let usdc = address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let amount = U256::from(2_500_000u64);
        let terms = PaymentTerms {
            token: usdc,
            amount,
            calls: vec![Call {
                target: usdc,
                data: IERC20::transferCall { to: address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"), amount }
                    .abi_encode()
                    .into(),
            }],
            expiration_timestamp: 1_800_000_000,
            recovery: address!("8093fef21c5d153456a7a39b3b09e69abc01a961"),
            salt: b256!("0000000000000000000000000000000000000000000000000000000000000001"),
            chain_id: 8453,
        };
        assert_eq!(terms.payment_address(factory), address!("2bdeD57b181534879E570AaD99131Ae37924eAF2"));
        assert!(terms.init_code_len() < MAX_INIT_CODE_BYTES);
    }

    #[test]
    fn reads_the_outcome_from_receipt_logs() {
        let payment = address!("00000000000000000000000000000000000000aa");
        let log = |topic: B256, data: Bytes| ReceiptLog { address: payment, topics: vec![topic], data };
        let amount = U256::from(7u64).abi_encode();
        assert_eq!(
            execution_outcome(&[log(IPayment::Settled::SIGNATURE_HASH, amount.clone().into())], payment),
            ExecutionOutcome::Settled
        );
        // Excess to recovery, then settled: still settled.
        let both = [
            log(IPayment::Recovered::SIGNATURE_HASH, amount.clone().into()),
            log(IPayment::Settled::SIGNATURE_HASH, amount.clone().into()),
        ];
        assert_eq!(execution_outcome(&both, payment), ExecutionOutcome::Settled);
        assert_eq!(
            execution_outcome(&[log(IPayment::Recovered::SIGNATURE_HASH, amount.into())], payment),
            ExecutionOutcome::Recovered { amount: U256::from(7u64) }
        );
        assert_eq!(execution_outcome(&[], payment), ExecutionOutcome::NoEvents);
    }
}
