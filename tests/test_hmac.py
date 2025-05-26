"""Tests for HMAC algorithm."""

import pytest

from src.jwt.algorithms import HMACAlgorithm


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
    hmac_jwk: dict | bytes, test_header: dict, test_payload: dict
):
    """Test HMAC signing and verification."""
    # Prepare signing input
    header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload_b64 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjJ9"
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Sign
    signature = HMACAlgorithm.sign(signing_input, hmac_jwk, "HS256")
    assert isinstance(signature, bytes)

    # Verify
    assert HMACAlgorithm.verify(signing_input, signature, hmac_jwk, "HS256")

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not HMACAlgorithm.verify(signing_input, invalid_signature, hmac_jwk, "HS256")


def test_hmac_unsupported_algorithm():
    """Test HMAC with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported HMAC algorithm: HS128"):
        HMACAlgorithm.sign(b"test", {}, "HS128")


def test_hmac_all_algorithms(hmac_jwk: dict | bytes):
    """Test all supported HMAC algorithms."""
    signing_input = b"test"

    for alg in ["HS256", "HS384", "HS512"]:
        hmac_jwk["alg"] = alg
        signature = HMACAlgorithm.sign(signing_input, hmac_jwk, alg)
        assert HMACAlgorithm.verify(signing_input, signature, hmac_jwk, alg)
