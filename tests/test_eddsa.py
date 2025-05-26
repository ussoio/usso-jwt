"""Tests for EdDSA algorithm."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.jwt.algorithms import EdDSAAlgorithm


def test_eddsa_load_key_from_jwk(eddsa_jwk: dict | bytes):
    """Test loading EdDSA key from JWK."""
    key = EdDSAAlgorithm.load_key(eddsa_jwk)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_eddsa_load_key_from_bytes(eddsa_private_key: ed25519.Ed25519PrivateKey):
    """Test loading EdDSA key from raw bytes."""
    key_bytes = eddsa_private_key.private_bytes_raw()
    key = EdDSAAlgorithm.load_key(key_bytes)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_eddsa_sign_verify(eddsa_jwk: dict | bytes):
    """Test EdDSA signing and verification."""
    signing_input = b"test"

    # Test EdDSA
    signature = EdDSAAlgorithm.sign(signing_input, eddsa_jwk, "EdDSA")
    assert isinstance(signature, bytes)
    assert EdDSAAlgorithm.verify(signing_input, signature, eddsa_jwk, "EdDSA")

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not EdDSAAlgorithm.verify(
        signing_input, invalid_signature, eddsa_jwk, "EdDSA"
    )


def test_eddsa_unsupported_algorithm():
    """Test EdDSA with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported EdDSA algorithm: Ed25519"):
        EdDSAAlgorithm.sign(b"test", {}, "Ed25519")
