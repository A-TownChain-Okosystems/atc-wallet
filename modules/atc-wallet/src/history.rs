// Copyright (c) 2026 A-TownChain-Okosystems — Apache-2.0
//! Deterministic, bounded transaction history.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryKind {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub tx_hash: [u8; 32],
    pub kind: HistoryKind,
    pub height: Option<u64>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct History {
    entries: Vec<HistoryEntry>,
}

impl History {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entry: HistoryEntry) {
        self.entries.push(entry);
        self.entries.sort_by_key(|item| (item.timestamp, item.height.unwrap_or(u64::MAX), item.tx_hash));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn page(&self, page: Page) -> Vec<HistoryEntry> {
        if page.limit == 0 || page.offset >= self.entries.len() {
            return Vec::new();
        }
        self.entries
            .iter()
            .skip(page.offset)
            .take(page.limit)
            .cloned()
            .collect()
    }

    pub fn filter(&self, kind: HistoryKind) -> Vec<HistoryEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8, timestamp: u64) -> HistoryEntry {
        HistoryEntry { tx_hash: [n; 32], kind: HistoryKind::Confirmed, height: Some(n as u64), timestamp }
    }

    #[test]
    fn entries_are_deterministically_ordered() {
        let mut history = History::new();
        history.push(entry(2, 20));
        history.push(entry(1, 10));
        assert_eq!(history.page(Page { offset: 0, limit: 2 })[0].tx_hash, [1; 32]);
    }

    #[test]
    fn pagination_is_bounded() {
        let mut history = History::new();
        history.push(entry(1, 10));
        assert!(history.page(Page { offset: 1, limit: 10 }).is_empty());
        assert!(history.page(Page { offset: 0, limit: 0 }).is_empty());
    }

    #[test]
    fn filtering_is_exact() {
        let mut history = History::new();
        let mut failed = entry(2, 20);
        failed.kind = HistoryKind::Failed;
        history.push(entry(1, 10));
        history.push(failed);
        assert_eq!(history.filter(HistoryKind::Failed).len(), 1);
    }
}
