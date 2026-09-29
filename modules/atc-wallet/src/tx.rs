// Copyright (c) 2026 A-TownChain-Okosystems — Apache-2.0
//! Canonical ATC transaction construction, hashing and Ed25519 signing.

use crate::keys::{KeyError, WalletKey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const NUMERIC_CHAIN_ID: u64 = 658467;
pub const TX_DOMAIN_V2: &[u8] = b"ATC-TX-DOMAIN-V2";
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxType {
    Transfer = 0,
    Stake = 1,
    Unstake = 2,
    Contract = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub chain_id: u64,
    pub tx_type: TxType,
    pub sender_did: String,
    pub recipient_did: Option<String>,
    pub amount: u128,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub nonce: u64,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    InvalidChainId,
    EmptySender,
    PayloadTooLarge,
    InvalidSignature,
    InvalidPublicKey,
}

impl Transaction {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TxError> {
        self.validate()?;
        let mut out = Vec::with_capacity(128 + self.payload.len());
        out.extend_from_slice(TX_DOMAIN_V2);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.push(self.tx_type as u8);
        put_bytes(&mut out, self.sender_did.as_bytes());

        match &self.recipient_did {
            Some(value) => {
                out.push(1);
                put_bytes(&mut out, value.as_bytes());
            }
            None => out.push(0),
        }

        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.gas_price.to_be_bytes());
        out.extend_from_slice(&self.gas_limit.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        put_bytes(&mut out, &self.payload);
        Ok(out)
    }

    pub fn tx_hash(&self) -> Result<[u8; 32], TxError> {
        Ok(Sha256::digest(self.signing_bytes()?).into())
    }

    pub fn sign(&self, key: &WalletKey) -> Result<[u8; 64], TxError> {
        Ok(key.sign(&self.signing_bytes()?).to_bytes())
    }

    pub fn verify(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), TxError> {
        self.validate()?;
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| TxError::InvalidPublicKey)?;
        key.verify(
            &self.signing_bytes()?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| TxError::InvalidSignature)
    }

    fn validate(&self) -> Result<(), TxError> {
        if self.chain_id != NUMERIC_CHAIN_ID {
            return Err(TxError::InvalidChainId);
        }
        if self.sender_did.is_empty() {
            return Err(TxError::EmptySender);
        }
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(TxError::PayloadTooLarge);
        }
        Ok(())
    }
}

impl From<KeyError> for TxError {
    fn from(value: KeyError) -> Self {
        match value {
            KeyError::InvalidPrivateKey => TxError::InvalidSignature,
            KeyError::InvalidPublicKey => TxError::InvalidPublicKey,
            KeyError::InvalidSignature => TxError::InvalidSignature,
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> Transaction {
        Transaction {
            chain_id: NUMERIC_CHAIN_ID,
            tx_type: TxType::Transfer,
            sender_did: "ATC-sender".into(),
            recipient_did: Some("ATC-recipient".into()),
            amount: 100,
            gas_price: 1,
            gas_limit: 1_000,
            nonce: 7,
            timestamp: 1_700_000_000,
            payload: b"hello".to_vec(),
        }
    }

    #[test]
    fn signing_roundtrip() {
        let key = WalletKey::from_seed([7u8; 32]);
        let tx = tx();
        let signature = tx.sign(&key).unwrap();
        assert!(tx.verify(&key.public_key(), &signature).is_ok());
    }

    #[test]
    fn amount_is_u128_in_canonical_preimage() {
        let mut tx = tx();
        tx.amount = u128::MAX;
        assert!(tx.signing_bytes().is_ok());
    }

    #[test]
    fn mutation_invalidates_signature() {
        let key = WalletKey::from_seed([7u8; 32]);
        let tx = tx();
        let signature = tx.sign(&key).unwrap();
        let mut altered = tx.clone();
        altered.amount += 1;
        assert!(altered.verify(&key.public_key(), &signature).is_err());
    }

    #[test]
    fn wrong_chain_is_rejected() {
        let mut tx = tx();
        tx.chain_id = 1;
        let key = WalletKey::from_seed([7u8; 32]);
        assert!(matches!(tx.sign(&key), Err(TxError::InvalidChainId)));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut tx = tx();
        tx.payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert!(matches!(tx.tx_hash(), Err(TxError::PayloadTooLarge)));
    }
}
