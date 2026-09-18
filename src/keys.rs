//! Secure Ed25519 wallet key management for A-TownChain.
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    secret: [u8; 32],
}

impl KeyPair {
    pub fn from_seed(seed: [u8; 32]) -> Self { Self { secret: seed } }

    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| KeyError::Randomness)?;
        Ok(Self { secret: seed })
    }

    pub fn signing_key(&self) -> SigningKey { SigningKey::from_bytes(&self.secret) }

    pub fn verifying_key(&self) -> VerifyingKey { self.signing_key().verifying_key() }

    pub fn public_key_bytes(&self) -> [u8; 32] { self.verifying_key().to_bytes() }

    pub fn secret_bytes(&self) -> [u8; 32] { self.secret }

    pub fn address(&self) -> String {
        let digest = Sha256::digest(self.public_key_bytes());
        format!("ATC{}", hex::encode(&digest[..16]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError { Randomness }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_derivation() {
        let a = KeyPair::from_seed([7u8; 32]);
        let b = KeyPair::from_seed([7u8; 32]);
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn address_is_canonical_shape() {
        let k = KeyPair::from_seed([9u8; 32]);
        assert_eq!(k.address().len(), 35);
        assert!(k.address().starts_with("ATC"));
    }
}
