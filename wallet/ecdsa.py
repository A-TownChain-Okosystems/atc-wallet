# Copyright (c) 2026 Michael Wroblewski / ShivaCore / A-TownChain-Okosystems. All Rights Reserved.
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class ECDSASigner:
    """Legacy/reference ECDSA helper.

    Deterministic transaction construction requires nonce and timestamp to be
    supplied by the caller. This module is not the canonical consensus signer;
    canonical L1 signing lives in src/tx.rs.
    """

    @staticmethod
    def generate_keypair() -> tuple:
        priv_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        priv_hex = format(priv_key.private_numbers().private_value, "064x")
        pub_hex = (
            priv_key.public_key()
            .public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
            .hex()
        )
        return priv_hex, pub_hex

    @staticmethod
    def sign(tx_data: dict, private_key_hex: str) -> str:
        message = json.dumps(tx_data, sort_keys=True, separators=(",", ":")).encode()
        priv_key = ec.derive_private_key(
            int(private_key_hex, 16), ec.SECP256K1(), default_backend()
        )
        return priv_key.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    @staticmethod
    def verify(tx_data: dict, signature_hex: str, public_key_hex: str) -> bool:
        try:
            message = json.dumps(tx_data, sort_keys=True, separators=(",", ":")).encode()
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), bytes.fromhex(public_key_hex)
            )
            public_key.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @staticmethod
    def build_tx(
        from_addr: str,
        to_addr: str,
        amount: int,
        fee: int,
        nonce: int,
        timestamp: int,
    ) -> dict:
        if amount < 0 or fee < 0 or nonce < 0 or timestamp < 0:
            raise ValueError("transaction numeric fields must be non-negative")
        return {
            "from": from_addr,
            "to": to_addr,
            "amount": amount,
            "fee": fee,
            "nonce": nonce,
            "timestamp": timestamp,
        }
