import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crypto import CryptoUtils
from wallet import Wallet\n\nSECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def test_python_wallet_uses_secp256k1_public_key_address():
    private_key = bytes([7]) * 32
    wallet = Wallet(private_key)
    assert wallet.public_key == CryptoUtils.public_key(private_key)
    expected = "ATC" + hashlib.sha256(wallet.public_key).hexdigest()[:32]
    assert wallet.address == expected\n    assert len(wallet.address) == 42\n    assert wallet.address.startswith("atc1")\n    assert Wallet.is_valid_address(wallet.address)


def test_python_signature_is_real_ecdsa_and_verifies():
    private_key = bytes([7]) * 32
    wallet = Wallet(private_key)
    wallet.receive(100)
    tx = wallet.sign_transaction(wallet.address, 1)
    digest = bytes.fromhex(tx["hash"])
    signature = bytes.fromhex(tx["signature"])
    public_key = bytes.fromhex(tx["public_key"])
    assert len(signature) == 64
    assert CryptoUtils.verify_signature(public_key, signature, digest)\n    order = SECP256K1_ORDER\n    r = int.from_bytes(signature[:32], "big")\n    s = int.from_bytes(signature[32:], "big")\n    assert r > 0 and r < order\n    assert s <= order // 2


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
    import json
    vector_path = Path(__file__).parent / "vectors" / "wallet_v1.json"
    vector = json.loads(vector_path.read_text())
    private_key = bytes.fromhex(vector["private_key"])
    assert hashlib.sha256(vector["message"].encode()).hexdigest() == vector["digest_sha256"]
    wallet = Wallet(private_key)
    assert wallet.public_key.hex() == vector["public_key_compressed"]
    assert wallet.address == vector["address"]
    signature = CryptoUtils.sign_digest(private_key, bytes.fromhex(vector["digest_sha256"]))
    assert signature.hex() == vector["signature_r_s"]
    assert CryptoUtils.verify_signature(wallet.public_key, signature, bytes.fromhex(vector["digest_sha256"]))
