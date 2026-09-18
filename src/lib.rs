//! Canonical ATC Wallet core.
//! Private keys never leave the wallet signing boundary.

pub mod balance;
pub mod gui;
pub mod history;
pub mod keys;
pub mod tx;\npub mod wallet;

pub use keys::KeyPair;
pub use tx::{SignedTransaction, Transaction, TransactionDomain, TxError};\npub use wallet::Wallet;
