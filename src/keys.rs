//! Canonical secp256k1 wallet key management for A-TownChain.
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

pub const ADDRESS_HRP: &str = "atc";
pub const ADDRESS_PAYLOAD_LEN: usize = 20;
pub const ADDRESS_LEN: usize = 37; // "atc1" + 32 data chars + 6 checksum chars

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    secret: [u8; 32],
    #[test]
    fn shared_cross_language_vector_matches() {
        let k = KeyPair::from_seed([1u8; 32]);
        let digest = Sha256::digest(b"atc-cross-language-vector-v1");
        let sig = k.sign_digest(&digest.into()).unwrap();
        assert_eq!(
            hex::encode(k.public_key_bytes()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(k.address(), "atc1pac4ht6afshdx2tctnhjnetz7u6g3j9zhhpqf3");
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "1f2773678b53c31890aa702760879c5cc2d1600f6025e7792d69348b457459f265d8c9c53125030d14e07faa01a1b3d72888f2a1c53668c43147940960f930d6"
        );
    }

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

    pub fn address_payload(&self) -> [u8; ADDRESS_PAYLOAD_LEN] {
        Sha256::digest(self.public_key_bytes())[..ADDRESS_PAYLOAD_LEN]
            .try_into()
            .expect("fixed-size address payload")
    }

    pub fn address(&self) -> String {
        bech32m_encode(ADDRESS_HRP, &self.address_payload())
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Signature, KeyError> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let signature = self.signing_key().sign_prehash(digest).map_err(|_| KeyError::SigningFailed)?;
        Ok(signature.normalize_s().unwrap_or(signature))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError { Randomness, InvalidSecret, SigningFailed }

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 { chk ^= g; }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    out.extend(bytes.iter().map(|b| b >> 5));
    out.push(0);
    out.extend(bytes.iter().map(|b| b & 31));
    out
}

fn convert_bits(data: &[u8], from: u8, to: u8) -> Vec<u8> {
    let mut acc = 0u32;
    let mut bits = 0u8;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        acc = (acc << from) | u32::from(value);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if bits != 0 { out.push(((acc << (to - bits)) & maxv) as u8); }
    out
}

fn bech32m_encode(hrp: &str, payload: &[u8]) -> String {
    let data = convert_bits(payload, 8, 5);
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0; 6]);
    let pm = polymod(&values) ^ 0x2bc830a3;
    let checksum = (0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8);
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for v in data { out.push(CHARSET[v as usize] as char); }
    for v in checksum { out.push(CHARSET[v as usize] as char); }
    out
}

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
    fn address_uses_20_byte_sha256_payload_and_bech32m() {
        let k = KeyPair::from_seed([9u8; 32]);
        assert!(k.address().starts_with("atc1"));
        assert_eq!(k.address_payload().len(), 20);
        assert_eq!(k.address().len(), ADDRESS_LEN);
        assert_eq!(k.public_key_bytes().len(), 33);
    }

    #[test]
    fn signature_is_low_s() {
        let k = KeyPair::from_seed([7u8; 32]);
        let digest = Sha256::digest(b"atc-wallet-test").into();
        let sig = k.sign_digest(&digest).unwrap();
        assert!(sig.normalize_s().is_none());
        assert_eq!(sig.to_bytes().len(), 64);
    }
}
