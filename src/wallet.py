# Copyright (c) 2026 Michael Wroblewski / ShivaCore / A-TownChain-Okosystems. All Rights Reserved.
"""Legacy/reference wallet helpers.

Wallet creation is deterministic at this boundary: callers provide the private
key material. Consensus transaction signing is implemented by src/tx.rs.
"""

import hashlib
import json

ATC_PREFIX = "ATC"
ADDRESS_LENGTH = 35


class Wallet:
    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self.address = self._derive_address(private_key)
        self.balance = 0
        self.nonce = 0

    @staticmethod
    def _derive_address(private_key: bytes) -> str:
        public_hash = hashlib.sha256(private_key).hexdigest()
        return f"{ATC_PREFIX}{public_hash[:32]}"

    @staticmethod
    def is_valid_address(address: str) -> bool:
        return (
            address.startswith(ATC_PREFIX)
            and len(address) == ADDRESS_LENGTH
            and all(c in "0123456789abcdef" for c in address[3:])
        )

    def sign_transaction(self, to: str, amount: int, fee: int = 0) -> dict:
        if not self.is_valid_address(to):
            raise ValueError(f"Invalid recipient address: {to}")
        if amount < 0 or fee < 0 or amount + fee > self.balance:
            raise ValueError("invalid or insufficient balance")

        tx = {
            "from": self.address,
            "to": to,
            "amount": amount,
            "fee": fee,
            "nonce": self.nonce,
        }
        tx_hash = hashlib.sha256(
            json.dumps(tx, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        tx["hash"] = tx_hash
        self.nonce += 1
        return tx

    def receive(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("amount must be non-negative")
        self.balance += amount

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "balance": self.balance,
            "nonce": self.nonce,
        }


def generate_wallet(private_key: bytes) -> Wallet:
    """Create a wallet from caller-provided private-key material."""
    if len(private_key) != 32:
        raise ValueError("private_key must be exactly 32 bytes")
    return Wallet(private_key)
