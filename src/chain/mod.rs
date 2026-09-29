//! Supported chains and the tokens an executable address may be funded with (gum-indexer must watch
//! every one of them), and the onchain maths of an executable address.

pub mod payment;
pub mod revert;

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_primitives::Address;

use crate::config::ChainConfig;

#[derive(Debug, Clone)]
pub struct TokenSpec {
    pub symbol: String,
    pub address: Address,
    pub decimals: u8,
}

#[derive(Debug, Clone)]
pub struct ChainSpec {
    pub name: String,
    pub chain_id: u64,
    /// Offered for new addresses. A disabled chain still resolves, so addresses created on it carry on.
    pub enabled: bool,
    pub tokens: Vec<TokenSpec>,
}

impl ChainSpec {
    /// The token at `address`, if an address on this chain may be funded with it.
    pub fn token(&self, address: Address) -> Option<&TokenSpec> {
        self.tokens.iter().find(|t| t.address == address)
    }

    /// "Base (8453)".
    pub fn label(&self) -> String {
        let mut name = self.name.clone();
        if let Some(first) = name.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        format!("{name} ({})", self.chain_id)
    }
}

#[derive(Debug, Default)]
pub struct Registry {
    by_id: BTreeMap<u64, Arc<ChainSpec>>,
}

impl Registry {
    pub fn from_config(chains: &BTreeMap<String, ChainConfig>) -> Self {
        let by_id = chains
            .iter()
            .map(|(name, chain)| {
                let spec = ChainSpec {
                    name: name.to_ascii_lowercase(),
                    chain_id: chain.chain_id,
                    enabled: chain.enabled,
                    tokens: chain
                        .tokens
                        .iter()
                        .map(|t| TokenSpec {
                            symbol: t.symbol.to_ascii_uppercase(),
                            address: t.address,
                            decimals: t.decimals,
                        })
                        .collect(),
                };
                (chain.chain_id, Arc::new(spec))
            })
            .collect();
        Self { by_id }
    }

    /// Any configured chain, enabled or not.
    pub fn chain(&self, chain_id: u64) -> Option<&Arc<ChainSpec>> {
        self.by_id.get(&chain_id)
    }

    /// The chains offered for new addresses.
    pub fn chains(&self) -> impl Iterator<Item = &Arc<ChainSpec>> {
        self.by_id.values().filter(|c| c.enabled)
    }

    pub fn chain_ids(&self) -> Vec<u64> {
        self.chains().map(|c| c.chain_id).collect()
    }

    pub fn disabled_chain_ids(&self) -> Vec<u64> {
        self.by_id.values().filter(|c| !c.enabled).map(|c| c.chain_id).collect()
    }
}
