"""Tests for ECDSA algorithm."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.jwt.algorithms import ECDSAAlgorithm
from src.jwt.exceptions import JWTInvalidSignatureError


def test_ecdsa_load_key_from_jwk(ecdsa_jwk: dict | bytes):
    """Test loading ECDSA key from JWK."""
    key = ECDSAAlgorithm.load_key(ecdsa_jwk, "ES256")
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_ecdsa_load_key_from_pem(ecdsa_private_key: ec.EllipticCurvePrivateKey):
    """Test loading ECDSA key from PEM."""
    pem = ecdsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = ECDSAAlgorithm.load_key(pem, "ES256")
    assert hasattr(key, "sign")
    assert hasattr(key, "private_bytes")


def test_ecdsa_sign_verify(ecdsa_jwk: dict | bytes):
    """Test ECDSA signing and verification."""
    signing_input = b"test"

    # Test ES256
    signature = ECDSAAlgorithm.sign(signing_input, ecdsa_jwk, "ES256")
    assert isinstance(signature, bytes)
    assert ECDSAAlgorithm.verify(signing_input, ecdsa_jwk, signature)

    # Test invalid signature
    invalid_signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
    with pytest.raises(JWTInvalidSignatureError):
        ECDSAAlgorithm.verify(signing_input, ecdsa_jwk, invalid_signature)


def test_ecdsa_unsupported_algorithm():
    """Test ECDSA with unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        ECDSAAlgorithm.sign(b"test", {}, "ES128")


def test_ecdsa_all_algorithms(ecdsa_jwk: dict | bytes):
    """Test all supported ECDSA algorithms."""
    signing_input = b"test"

    for alg in ["ES256", "ES384", "ES512"]:
        ecdsa_jwk["alg"] = alg
        signature = ECDSAAlgorithm.sign(signing_input, ecdsa_jwk, alg)
        assert ECDSAAlgorithm.verify(signing_input, ecdsa_jwk, signature)
