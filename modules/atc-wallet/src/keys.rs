// Copyright (c) 2026 A-TownChain-Okosystems — Apache-2.0
//! Trusted secp256k1 transaction/account key management.
//!
//! Transaction signatures use ECDSA/secp256k1 with RFC6979 deterministic
//! nonce generation, SHA-256 prehashing and mandatory low-S normalization.

use k256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

pub const PRIVATE_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 33;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    HighS,
    SigningFailure,
}

pub struct WalletKey(SigningKey);

impl WalletKey {
    pub fn from_private_key_bytes(bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<Self, KeyError> {
        SigningKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|_| KeyError::InvalidPrivateKey)
    }

    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = [0u8; PRIVATE_KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|_| KeyError::InvalidPrivateKey)?;
        Self::from_private_key_bytes(&bytes)
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed secp256k1 public key is exactly 33 bytes")
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, KeyError> {
        let prehash = Sha256::digest(message);
        self.0
            .sign_prehash(&prehash)
            .map(|signature: Signature| signature.normalize_s().unwrap_or(signature))
            .map_err(|_| KeyError::SigningFailure)
    }

    pub fn verify(
        public_key: &[u8; PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<(), KeyError> {
        let key =
            VerifyingKey::from_sec1_bytes(public_key).map_err(|_| KeyError::InvalidPublicKey)?;
        let signature =
            Signature::try_from(signature.as_slice()).map_err(|_| KeyError::InvalidSignature)?;

        if signature.normalize_s().is_some() {
            return Err(KeyError::HighS);
        }

        let prehash = Sha256::digest(message);
        key.verify_prehash(&prehash, &signature)
            .map_err(|_| KeyError::InvalidSignature)
    }
}

impl std::fmt::Debug for WalletKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_derives_stable_public_key() {
        let a = WalletKey::from_private_key_bytes(&[7u8; 32]).unwrap();
        let b = WalletKey::from_private_key_bytes(&[7u8; 32]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = WalletKey::from_private_key_bytes(&[7u8; 32]).unwrap();
        let signature = key.sign(b"atc-wallet").unwrap();
        assert!(WalletKey::verify(
            &key.public_key(),
            b"atc-wallet",
            &signature.to_bytes().into()
        )
        .is_ok());
    }

    #[test]
    fn high_s_is_rejected() {
        let key = WalletKey::from_private_key_bytes(&[7u8; 32]).unwrap();
        let signature = key.sign(b"atc-wallet").unwrap();
        assert!(signature.normalize_s().is_none());
    }

    #[test]
    fn modified_message_is_rejected() {
        let key = WalletKey::from_private_key_bytes(&[7u8; 32]).unwrap();
        let signature = key.sign(b"atc-wallet").unwrap();
        assert!(WalletKey::verify(
            &key.public_key(),
            b"tampered",
            &signature.to_bytes().into()
        )
        .is_err());
    }
}
