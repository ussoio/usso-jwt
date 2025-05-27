"""Tests for HMAC algorithm."""

import pytest

from src.usso_jwt.algorithms import HMACAlgorithm, HMACKey
from src.usso_jwt.core import b64url_decode

def test_hmac_load_key_from_jwk(hmac_jwk: dict | bytes):
    """Test loading HMAC key from JWK."""
    key = HMACAlgorithm.load_key(hmac_jwk)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_hmac_load_key_from_bytes(hmac_key: bytes):
    """Test loading HMAC key from raw bytes."""
    key = HMACAlgorithm.load_key(hmac_key)
    assert isinstance(key, bytes)
    assert key == hmac_key


def test_hmac_sign_verify(
    hmac_jwk: dict | bytes
):
    """Test HMAC signing and verification."""
    # Prepare signing input
    header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload_b64 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9"
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Sign
    signature = HMACAlgorithm.sign(data=signing_input, key=hmac_jwk, alg="HS256")
    assert isinstance(signature, bytes)

    # Verify
    assert HMACAlgorithm.verify(data=signing_input, signature=signature, key=hmac_jwk, alg="HS256")

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not HMACAlgorithm.verify(data=signing_input, signature=invalid_signature, key=hmac_jwk, alg="HS256")


def test_hmac_unsupported_algorithm():
    """Test HMAC with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported HMAC algorithm: HS128"):
        HMACAlgorithm.sign(data=b"test", key={}, alg="HS128")


def test_hmac_all_algorithms(hmac_jwk: dict | bytes):
    """Test all supported HMAC algorithms."""
    signing_input = b"test"

    for alg in ["HS256", "HS384", "HS512"]:
        hmac_jwk["alg"] = alg
        signature = HMACAlgorithm.sign(data=signing_input, key=hmac_jwk, alg=alg)
        assert HMACAlgorithm.verify(data=signing_input, signature=signature, key=hmac_jwk, alg=alg)


def test_hmac_key_generate():
    """Test HMAC key generation."""
    key = HMACKey.generate(algorithm="HS256")
    assert key.algorithm == "HS256"
    assert key.type == "HMAC"
    assert len(key.key) == 32


def test_hmac_key_load_jwk(hmac_jwk: dict | bytes):
    """Test HMAC key loading from JWK."""
    key = HMACKey.load_jwk(hmac_jwk)
    assert key.algorithm == "HS256"
    assert key.type == "HMAC"
    assert len(key.key) == 32


def test_hmac_key_sign_verify(hmac_jwk: dict | bytes):
    """Test HMAC key signing and verification."""
    key = HMACKey.generate(algorithm="HS256")
    signature = key.sign(data=b"test")
    assert key.verify(data=b"test", signature=signature)


def test_hmac_key_type(hmac_jwk: dict | bytes):
    """Test HMAC key type."""
    key = HMACKey.load_jwk(hmac_jwk)
    assert key.type == "HMAC"
