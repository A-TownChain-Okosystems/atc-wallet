// Copyright (c) 2026 Michael Wroblewski / ShivaCore / A-TownChain-Okosystems. All Rights Reserved.
//! Trusted Ed25519 key management for the canonical ATC wallet core.
//!
//! Private key material is kept in this module's Rust types and is never
//! formatted through Debug/Display. Higher layers should pass only public
//! material or signatures across their boundaries.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
}

#[derive(Clone)]
pub struct WalletKey {
    signing_key: SigningKey,
}

impl WalletKey {
    /// Construct a key from exactly 32 bytes of seed material.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Generate a key using operating-system CSPRNG entropy.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| KeyError::InvalidPrivateKey)?;
        Ok(Self::from_seed(seed))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), KeyError> {
        let key =
            VerifyingKey::from_bytes(public_key).map_err(|_| KeyError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(signature);
        key.verify(message, &signature)
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
        let a = WalletKey::from_seed([7u8; 32]);
        let b = WalletKey::from_seed([7u8; 32]);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = WalletKey::from_seed([7u8; 32]);
        let signature = key.sign(b"atc-wallet");
        assert!(WalletKey::verify(&key.public_key(), b"atc-wallet", &signature.to_bytes()).is_ok());
    }

    #[test]
    fn modified_message_is_rejected() {
        let key = WalletKey::from_seed([7u8; 32]);
        let signature = key.sign(b"atc-wallet");
        assert!(WalletKey::verify(&key.public_key(), b"tampered", &signature.to_bytes()).is_err());
    }
}
