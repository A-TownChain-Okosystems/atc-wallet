# Copyright (c) 2026 Michael Wroblewski / ShivaCore / A-TownChain-Okosystems. All Rights Reserved.
"""ATC Wallet — Python compatibility/UI facade.

The Rust wallet core is canonical. Python uses the same secp256k1 key/address
scheme and deterministic RFC6979 ECDSA with explicit low-S normalization.
"""

import hashlib
import json
import os

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string, sigdecode_string

from crypto import CryptoUtils

ADDRESS_HRP = "atc"
ADDRESS_PAYLOAD_LEN = 20
ADDRESS_LENGTH = 42
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_MAP = {c: i for i, c in enumerate(_CHARSET)}


def _polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                chk ^= generator
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data, from_bits, to_bits, pad=True):
    acc = 0
    bits = 0
    result = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("invalid bit-conversion value")
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & max_value)
    if bits:
        if not pad:
            if bits >= from_bits or ((acc << (to_bits - bits)) & max_value):
                raise ValueError("non-canonical Bech32 padding")
        else:
            result.append((acc << (to_bits - bits)) & max_value)
    return result


def encode_address(payload):
    if len(payload) != ADDRESS_PAYLOAD_LEN:
        raise ValueError("ATC address payload must be 20 bytes")
    data = _convert_bits(payload, 8, 5)
    values = _hrp_expand(ADDRESS_HRP) + data + [0] * 6
    polymod = _polymod(values) ^ 0x2BC830A3
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return ADDRESS_HRP + "1" + "".join(_CHARSET[v] for v in data + checksum)


def decode_address(address):
    if not address.startswith(ADDRESS_HRP + "1"):
        raise ValueError("invalid ATC address HRP")
    parts = address.split("1", 1)
    if len(parts[1]) < 6:
        raise ValueError("invalid ATC address length")
    values = [_CHARSET_MAP.get(c, -1) for c in parts[1]]
    if -1 in values:
        raise ValueError("invalid Bech32m character")
    if _polymod(_hrp_expand(parts[0]) + values) != 0x2BC830A3:
        raise ValueError("invalid Bech32m checksum")
    data = values[:-6]
    payload = bytes(_convert_bits(data, 5, 8, pad=False))
    if len(payload) != ADDRESS_PAYLOAD_LEN:
        raise ValueError("invalid ATC address payload")
    return payload


class Wallet:
    """ATC wallet facade using canonical secp256k1 keys."""

    def __init__(self, private_key: bytes):
        if len(private_key) != 32:
            raise ValueError("private_key must be 32 bytes")
        self._key = SigningKey.from_string(private_key, curve=SECP256k1, hashfunc=hashlib.sha256)
        self.private_key = private_key
        self.public_key = self._key.get_verifying_key().to_string(encoding="compressed")
        self.address = self._derive_address(private_key)
        self.balance = 0
        self.nonce = 0

    @staticmethod
    def _derive_address(private_key: bytes) -> str:
        public_key = CryptoUtils.public_key(private_key)
        return encode_address(hashlib.sha256(public_key).digest()[:ADDRESS_PAYLOAD_LEN])

    @staticmethod
    def is_valid_address(address: str) -> bool:
        try:
            decode_address(address)
            return True
        except ValueError:
            return False

    def sign_transaction(self, to: str, amount: float, fee: float = 0.001) -> dict:
        if not self.is_valid_address(to):
            raise ValueError(f"Invalid recipient address: {to}")
        if amount + fee > self.balance:
            raise ValueError("Insufficient balance")
        tx = {
            "from": self.address, "to": to, "amount": amount,
            "fee": fee, "nonce": self.nonce,
        }
        canonical = json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        digest = hashlib.sha256(canonical).digest()
        signature = self._key.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode_string
        )
        r, s = sigdecode_string(signature, self._key.curve.generator.order)
        order = self._key.curve.generator.order
        if s > order // 2:
            s = order - s
            signature = sigencode_string(r, s, order)
        tx["hash"] = digest.hex()
        tx["public_key"] = self.public_key.hex()
        tx["signature"] = signature.hex()
        self.nonce += 1
        return tx


    def receive(self, amount: float) -> None:
        self.balance += amount

    def to_dict(self) -> dict:
        return {"address": self.address, "balance": self.balance, "nonce": self.nonce}


def generate_wallet() -> Wallet:
    while True:
        private_key = os.urandom(32)
        try:
            return Wallet(private_key)
        except (ValueError, AssertionError):
            continue


if __name__ == "__main__":
    wallet = generate_wallet()
    print(f"Address: {wallet.address}")
    print(f"Valid: {Wallet.is_valid_address(wallet.address)}")
