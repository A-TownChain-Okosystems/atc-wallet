//! Deterministic local transaction history.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRecord {
    pub tx_id: [u8; 32],
    pub nonce: u64,
    pub confirmed_height: Option<u64>,
    pub success: bool,
}

#[derive(Debug, Default, Clone)]
pub struct History {
    records: Vec<TransactionRecord>,
}

impl History {
    pub fn push(&mut self, record: TransactionRecord) { self.records.push(record); }
    pub fn records(&self) -> &[TransactionRecord] { &self.records }
}
