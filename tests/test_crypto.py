import hashlib
import json
import sys
from pathlib import Path

from ecdsa.curves import SECP256k1
from ecdsa.util import sigdecode_string

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crypto import CryptoUtils  # noqa: E402
from wallet import Wallet  # noqa: E402


def test_python_wallet_uses_secp256k1_public_key_address():
    private_key = bytes([7]) * 32
    wallet = Wallet(private_key)
    assert wallet.public_key == CryptoUtils.public_key(private_key)
    assert len(wallet.public_key) == 33
    assert len(wallet.address) == 42
    assert wallet.address.startswith("atc1")
    assert Wallet.is_valid_address(wallet.address)


def test_python_signature_is_real_ecdsa_and_verifies():
    private_key = bytes([7]) * 32
    wallet = Wallet(private_key)
    wallet.receive(100)
    tx = wallet.sign_transaction(wallet.address, 1)
    digest = bytes.fromhex(tx["hash"])
    signature = bytes.fromhex(tx["signature"])
    public_key = bytes.fromhex(tx["public_key"])

    assert len(signature) == 64
    assert CryptoUtils.verify_signature(public_key, signature, digest)

    order = SECP256k1.generator.order()
    r, s = sigdecode_string(signature, order)
    assert 0 < r < order
    assert s <= order // 2


def test_python_signature_rejects_modified_digest():
    private_key = bytes([7]) * 32
    wallet = Wallet(private_key)
    wallet.receive(100)
    tx = wallet.sign_transaction(wallet.address, 1)
    digest = bytearray.fromhex(tx["hash"])
    digest[0] ^= 1
    assert not CryptoUtils.verify_signature(
        bytes.fromhex(tx["public_key"]),
        bytes.fromhex(tx["signature"]),
        bytes(digest),
    )


def test_cross_language_vector():
    vector_path = Path(__file__).parent / "vectors" / "wallet_v1.json"
    vector = json.loads(vector_path.read_text())
    private_key = bytes.fromhex(vector["private_key"])
    digest = hashlib.sha256(vector["message"].encode()).digest()

    assert digest.hex() == vector["digest_sha256"]

    wallet = Wallet(private_key)
    assert wallet.public_key.hex() == vector["public_key_compressed"]
    assert wallet.address == vector["address"]

    signature = CryptoUtils.sign_digest(private_key, digest)
    assert signature.hex() == vector["signature_r_s"]
    assert CryptoUtils.verify_signature(
        wallet.public_key,
        signature,
        digest,
    )
