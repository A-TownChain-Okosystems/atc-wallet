// Copyright (c) 2026 A-TownChain-Okosystems — Apache-2.0
//! Canonical ATC transaction contract V2.
//! Transaction authorization: secp256k1 ECDSA, RFC6979, low-S.
//! Identity keys remain a separate Ed25519 concern.

use k256::ecdsa::{signature::{hazmat::{PrehashSigner, PrehashVerifier}}, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const TX_DOMAIN_V2: &str = "ATC-TX-DOMAIN-V2";
pub const CHAIN_ID: u64 = 658467;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV2 {
    pub nonce: u64,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub amount: u128,
    pub fee: u128,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxV2Error {
    InvalidDomain,
    InvalidKey,
    InvalidSignature,
    NonceOverflow,
}

fn field(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    out.extend_from_slice(&(key.len() as u32).to_be_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

pub fn signing_preimage(tx: &TransactionV2) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, b"domain", TX_DOMAIN_V2.as_bytes());
    field(&mut out, b"chain_id", &CHAIN_ID.to_be_bytes());
    field(&mut out, b"nonce", &tx.nonce.to_be_bytes());
    field(&mut out, b"sender", &tx.sender);
    field(&mut out, b"recipient", &tx.recipient);
    field(&mut out, b"amount", &tx.amount.to_be_bytes());
    field(&mut out, b"fee", &tx.fee.to_be_bytes());
    field(&mut out, b"payload", &tx.payload);
    out
}

pub fn digest(tx: &TransactionV2) -> [u8; 32] {
    Sha256::digest(signing_preimage(tx)).into()
}

pub fn sign(tx: &TransactionV2, key: &SigningKey) -> Result<Signature, TxV2Error> {
    let digest = digest(tx);
    let mut sig = key.sign_prehash(&digest).map_err(|_| TxV2Error::InvalidKey)?;
    if let Some(low_s) = sig.normalize_s() {
        sig = low_s;
    }
    Ok(sig)
}

pub fn verify(tx: &TransactionV2, key: &VerifyingKey, sig: &Signature) -> Result<(), TxV2Error> {
    if sig.normalize_s().is_some() {
        return Err(TxV2Error::InvalidSignature);
    }
    key.verify_prehash(&digest(tx), sig).map_err(|_| TxV2Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> TransactionV2 {
        TransactionV2 {
            nonce: 7,
            sender: vec![2; 33],
            recipient: vec![3; 33],
            amount: u128::MAX,
            fee: u128::MAX - 1,
            payload: b"ATC-V2".to_vec(),
        }
    }

    #[test]
    fn u128_boundaries_are_fixed_16_byte_big_endian() {
        let mut t = tx();
        assert_eq!(t.amount.to_be_bytes().len(), 16);
        assert_eq!(t.fee.to_be_bytes().len(), 16);
        let a = signing_preimage(&t);
        t.amount -= 1;
        assert_ne!(a, signing_preimage(&t));
    }

    #[test]
    fn v2_roundtrip_and_low_s() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let sig = sign(&tx(), &key).unwrap();
        assert!(sig.normalize_s().is_none());
        assert!(verify(&tx(), &key.verifying_key(), &sig).is_ok());
    }

    #[test]
    fn legacy_domain_is_not_used() {
        assert_ne!(TX_DOMAIN_V2, "ATC-TX-DOMAIN");
    }
}
