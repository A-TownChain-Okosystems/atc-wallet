//! Secure secp256k1 wallet key management for A-TownChain.
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
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
        SigningKey::from_bytes((&seed).into()).map_err(|_| KeyError::InvalidSecret)?;
        Ok(Self { secret: seed })
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes((&self.secret).into())
            .expect("KeyPair invariant: secret must be a valid secp256k1 scalar")
    }

    pub fn verifying_key(&self) -> VerifyingKey { self.signing_key().verifying_key().clone() }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn secret_bytes(&self) -> [u8; 32] { self.secret }

    pub fn address(&self) -> String {
        let digest = Sha256::digest(self.public_key_bytes());
        format!("ATC{}", hex::encode(&digest[..16]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError { Randomness, InvalidSecret }

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
        assert_eq!(k.public_key_bytes().len(), 33);
    }

    #[test]
    fn address_depends_on_public_key_not_private_key_bytes() {
        let k = KeyPair::from_seed([9u8; 32]);
        let expected = format!(
            "ATC{}",
            hex::encode(&Sha256::digest(k.public_key_bytes())[..16])
        );
        assert_eq!(k.address(), expected);
    }
}
