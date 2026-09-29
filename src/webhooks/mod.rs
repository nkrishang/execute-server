//! Webhooks in both directions: verified deliveries from gum-indexer / gum-engine, and signed
//! deliveries to apps (`X-Execute-Signature`, the same scheme).

pub mod inbound;
pub mod sign;
pub mod target;
