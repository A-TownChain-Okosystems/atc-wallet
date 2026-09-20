# Copyright (c) 2026 Michael Wroblewski / ShivaCore / A-TownChain-Okosystems. All Rights Reserved.
"""ATC Crypto — canonical secp256k1 signing and verification utilities."""

import hashlib
import hmac

from ecdsa import BadSignatureError, SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string


class CryptoUtils:
    """Cryptographic helpers for ATC wallet operations.

    Python is a compatibility/UI boundary. The Rust wallet remains the
    canonical trusted implementation; this module uses the same secp256k1
    algorithm and raw 64-byte (r||s) signature representation.
    """

    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_bytes(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hmac_sha256(key: bytes, message: bytes) -> bytes:
        return hmac.new(key, message, hashlib.sha256).digest()

    @staticmethod
    def sign_digest(private_key: bytes, digest: bytes) -> bytes:
        if len(private_key) != 32 or len(digest) != 32:
            raise ValueError("private_key and digest must both be 32 bytes")
        key = SigningKey.from_string(private_key, curve=SECP256k1, hashfunc=hashlib.sha256)
        signature = key.sign_digest_deterministic(
            digest,
            hashfunc=hashlib.sha256,
            sigencode=sigencode_string,
        )
        r, s = sigdecode_string(signature, key.curve.generator.order)
        order = key.curve.generator.order
        if s > order // 2:
            s = order - s
        return sigencode_string(r, s, order)

    @staticmethod
    def verify_signature(public_key: bytes, signature: bytes, digest: bytes) -> bool:
        if len(digest) != 32:
            return False
        try:
            key = VerifyingKey.from_string(public_key, curve=SECP256k1)
            return key.verify_digest(signature, digest, sigdecode=sigdecode_string)
        except (BadSignatureError, ValueError):
            return False

    @staticmethod
    def public_key(private_key: bytes) -> bytes:
        if len(private_key) != 32:
            raise ValueError("private_key must be 32 bytes")
        key = SigningKey.from_string(private_key, curve=SECP256k1, hashfunc=hashlib.sha256)
        return key.get_verifying_key().to_string(encoding="compressed")

    @staticmethod
    def derive_key(seed: bytes, index: int) -> bytes:
        return hashlib.sha256(seed + index.to_bytes(4, "big")).digest()

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
