"""Tests for RSA algorithm."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.jwt.algorithms import RSAAlgorithm


def test_rsa_load_key_from_jwk(rsa_jwk: dict | bytes):
    """Test loading RSA key from JWK."""
    key = RSAAlgorithm.load_key(rsa_jwk)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_rsa_load_key_from_pem(rsa_private_key: rsa.RSAPrivateKey):
    """Test loading RSA key from PEM."""
    pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = RSAAlgorithm.load_key(pem)
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_rsa_sign_verify(rsa_jwk: dict | bytes):
    """Test RSA signing and verification."""
    signing_input = b"test"

    # Test RS256
    signature = RSAAlgorithm.sign(signing_input, rsa_jwk, "RS256")
    assert isinstance(signature, bytes)
    assert RSAAlgorithm.verify(signing_input, signature, rsa_jwk, "RS256")

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    assert not RSAAlgorithm.verify(signing_input, invalid_signature, rsa_jwk, "RS256")


def test_rsa_unsupported_algorithm():
    """Test RSA with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported RSA algorithm: RS128"):
        RSAAlgorithm.sign(b"test", {}, "RS128")


def test_rsa_all_algorithms(rsa_jwk: dict | bytes):
    """Test all supported RSA algorithms."""
    signing_input = b"test"

    for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]:
        rsa_jwk["alg"] = alg
        signature = RSAAlgorithm.sign(signing_input, rsa_jwk, alg)
        assert RSAAlgorithm.verify(signing_input, signature, rsa_jwk, alg)
