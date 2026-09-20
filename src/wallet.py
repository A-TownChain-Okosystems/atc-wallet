# Copyright (c) 2026 Michael Wroblewski / ShivaCore / A-TownChain-Okosystems. All Rights Reserved.
"""ATC Wallet — Python compatibility/UI facade.

The Rust wallet core is canonical. Python uses the same secp256k1 key/address
scheme and signs transaction digests with deterministic RFC6979 ECDSA.
"""

import hashlib
import json
import os

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string

from crypto import CryptoUtils

ATC_PREFIX = "ATC"
ADDRESS_LENGTH = 35


class Wallet:
    """ATC wallet facade using canonical secp256k1 keys."""

    def __init__(self, private_key: bytes):
        if len(private_key) != 32:
            raise ValueError("private_key must be 32 bytes")
        # Reject invalid secp256k1 private scalars at construction time.
        self._key = SigningKey.from_string(
            private_key, curve=SECP256k1, hashfunc=hashlib.sha256
        )
        self.private_key = private_key
        self.public_key = self._key.get_verifying_key().to_string(encoding="compressed")
        self.address = self._derive_address(private_key)
        self.balance = 0
        self.nonce = 0

    @staticmethod
    def _derive_address(private_key: bytes) -> str:
        """Derive the canonical ATC address from the compressed public key."""
        if len(private_key) != 32:
            raise ValueError("private_key must be 32 bytes")
        public_key = CryptoUtils.public_key(private_key)
        public_hash = hashlib.sha256(public_key).hexdigest()
        return f"{ATC_PREFIX}{public_hash[:32]}"

    @staticmethod
    def is_valid_address(address: str) -> bool:
        return (
            address.startswith(ATC_PREFIX)
            and len(address) == ADDRESS_LENGTH
            and all(c in "0123456789abcdef" for c in address[3:])
        )

    def sign_transaction(self, to: str, amount: float, fee: float = 0.001) -> dict:
        """Create a deterministic transaction digest and real secp256k1 signature."""
        if not self.is_valid_address(to):
            raise ValueError(f"Invalid recipient address: {to}")
        if amount + fee > self.balance:
            raise ValueError("Insufficient balance")

        tx = {
            "from": self.address,
            "to": to,
            "amount": amount,
            "fee": fee,
            "nonce": self.nonce,
        }
        canonical = json.dumps(
            tx, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).digest()
        signature = self._key.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode_string
        )
        tx["hash"] = digest.hex()
        tx["public_key"] = self.public_key.hex()
        tx["signature"] = signature.hex()
        self.nonce += 1
        return tx

    def receive(self, amount: float) -> None:
        self.balance += amount

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "balance": self.balance,
            "nonce": self.nonce,
        }


def generate_wallet() -> Wallet:
    """Generate a new random secp256k1 wallet."""
    while True:
        private_key = os.urandom(32)
        try:
            return Wallet(private_key)
        except ValueError:
            continue


if __name__ == "__main__":
    wallet = generate_wallet()
    print(f"Address: {wallet.address}")
    print(f"Valid: {Wallet.is_valid_address(wallet.address)}")
