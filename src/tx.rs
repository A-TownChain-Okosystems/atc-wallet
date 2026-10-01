// Copyright (c) 2026 A-TownChain-Okosystems — Apache-2.0
//! Canonical ATC-TX-DOMAIN-V2 transaction signing.
//!
//! Consensus/account signatures use secp256k1 ECDSA with RFC6979,
//! SHA-256 and low-S normalization. The authenticated transaction amount
//! is u128 and is encoded as exactly 16 big-endian bytes.

use k256::ecdsa::{
    signature::{DigestSigner, DigestVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

pub const NUMERIC_CHAIN_ID: u64 = 658467;
pub const TX_DOMAIN_V2: &[u8] = b"ATC-TX-DOMAIN-V2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub chain_id: u64,
    pub tx_type: u8,
    pub sender: Vec<u8>,
    pub recipient: Option<Vec<u8>>,
    pub amount: u128,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    InvalidChainId,
    InvalidSender,
    InvalidRecipient,
    InvalidSignature,
}

impl Transaction {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TxError> {
        if self.chain_id != NUMERIC_CHAIN_ID {
            return Err(TxError::InvalidChainId);
        }
        if self.sender.is_empty() {
            return Err(TxError::InvalidSender);
        }

        let mut out = Vec::with_capacity(128 + self.payload.len());
        out.extend_from_slice(TX_DOMAIN_V2);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.push(self.tx_type);
        put_bytes_u32(&mut out, &self.sender);

        match &self.recipient {
            Some(value) => {
                out.push(1);
                put_bytes_u32(&mut out, value);
            }
            None => out.push(0),
        }

        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.gas_price.to_be_bytes());
        out.extend_from_slice(&self.gas_limit.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        put_bytes_u32(&mut out, &self.payload);
        Ok(out)
    }

    pub fn signing_digest(&self) -> Result<Sha256, TxError> {
        Ok(Sha256::new_with_prefix(self.signing_bytes()?))
    }

    pub fn sign(&self, key: &SigningKey) -> Result<Signature, TxError> {
        let digest = self.signing_digest()?;
        let signature: Signature = key.sign_digest(digest);
        Ok(signature.normalize_s().unwrap_or(signature))
    }

    pub fn verify(
        &self,
        public_key: &VerifyingKey,
        signature: &Signature,
    ) -> Result<(), TxError> {
        let digest = self.signing_digest()?;
        public_key
            .verify_digest(digest, signature)
            .map_err(|_| TxError::InvalidSignature)
    }

    pub fn compressed_public_key(public_key: &VerifyingKey) -> [u8; 33] {
        let encoded = public_key.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        out
    }
}

fn put_bytes_u32(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> Transaction {
        Transaction {
            chain_id: NUMERIC_CHAIN_ID,
            tx_type: 0,
            sender: vec![1; 33],
            recipient: Some(vec![2; 33]),
            amount: u128::MAX,
            gas_price: 1,
            gas_limit: 1000,
            nonce: 7,
            timestamp: 1_700_000_000,
            payload: b"hello".to_vec(),
        }
    }

    #[test]
    fn u128_is_fixed_16_byte_big_endian() {
        let bytes = tx().signing_bytes().unwrap();
        let offset = TX_DOMAIN_V2.len() + 8 + 1 + 4 + 33 + 1 + 4 + 33;
        assert_eq!(&bytes[offset..offset + 16], &[0xff; 16]);
    }

    #[test]
    fn signature_roundtrip_and_compressed_key() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let tx = tx();
        let sig = tx.sign(&key).unwrap();
        assert!(tx.verify(&key.verifying_key(), &sig).is_ok());
        assert_eq!(TxSignature::is_low_s(&sig), true);
        assert_eq!(Transaction::compressed_public_key(&key.verifying_key()).len(), 33);
    }

    #[test]
    fn mutation_invalidates_signature() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let tx = tx();
        let sig = tx.sign(&key).unwrap();
        let mut altered = tx.clone();
        altered.amount -= 1;
        assert!(altered.verify(&key.verifying_key(), &sig).is_err());
    }

    #[test]
    fn wrong_chain_is_rejected() {
        let mut tx = tx();
        tx.chain_id = 1;
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        assert!(matches!(tx.sign(&key), Err(TxError::InvalidChainId)));
    }

    #[test]
    fn legacy_domain_is_not_present() {
        assert!(!String::from_utf8_lossy(TX_DOMAIN_V2).contains("ATC-TX-DOMAIN"));
    }
}

struct TxSignature;

impl TxSignature {
    fn is_low_s(signature: &Signature) -> bool {
        signature.normalize_s().is_none()
    }
}
