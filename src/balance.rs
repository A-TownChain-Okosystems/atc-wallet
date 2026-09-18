//! Local wallet account view. On-chain balances remain authoritative.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balance {
    pub available: u64,
    pub staked: u64,
}

impl Balance {
    pub fn total(&self) -> u64 { self.available.saturating_add(self.staked) }
}
